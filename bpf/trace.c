// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// Event type constants
#define EVENT_OPENAT  1
#define EVENT_EXIT    2
#define EVENT_CONNECT 3  // placeholder for future

// All events start with type field for Go dispatcher
struct openat_event {
    __u32 type;      // EVENT_OPENAT
    __u32 pid;
    __u32 tgid;
    __u64 timestamp_ns;
    __u64 enter_time_ns;  // for latency calculation
    char comm[TASK_COMM_LEN];
    char filename[256];
} __attribute__((packed));

struct exit_event {
    __u32 type;      // EVENT_EXIT
    __u32 pid;
    __u32 tgid;
    __u32 ppid;

    __u64 start_time_ns;
    __u64 exit_time_ns;

    __s32 exit_code;
    __s32 signal;
    __u8 group_dead;

    char comm[TASK_COMM_LEN];
} __attribute__((packed));

struct process_info {
    u32 ppid;
    u32 rpid;
    char fork_comm[TASK_COMM_LEN];
    char current_comm[TASK_COMM_LEN];
};

// map for allowed command to be filtered out
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} allowed_commands SEC(".maps");

// map for ignored commands
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} ignored_commands SEC(".maps");

// map: child -> root
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct process_info);
} child_root SEC(".maps");

// map: track openat enter times for latency calculation
// key: (pid << 32) | tid to handle multi-threaded processes
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, __u64);
} openat_start SEC(".maps");

// Single unified ring buffer for all events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

static __always_inline int is_noise(const char *filename)
{
    char buf[64];
    int len = bpf_probe_read_user_str(buf, sizeof(buf), filename);
    if (len <= 0)
        return 1; // unreadable is noisy

    int slen = len - 1; // excluding NUL

    // common noisy prefixes
    if (slen >= 4 && buf[0] == '/' && buf[1] == 'd' && buf[2] == 'e' && buf[3] == 'v')
        return 1;
    if (slen >= 5 && buf[0] == '/' && buf[1] == 'p' && buf[2] == 'r' && buf[3] == 'o' && buf[4] == 'c')
        return 1;
    if (slen >= 4 && buf[0] == '/' && buf[1] == 's' && buf[2] == 'y' && buf[3] == 's')
        return 1;
    if (slen >= 5 && buf[0] == '/' && buf[1] == 'u' && buf[2] == 's' && buf[3] == 'r' && buf[4] == '/')
        return 1; // /usr/lib, /usr/share, etc
    if (slen >= 4 && buf[0] == '/' && buf[1] == 'l' && buf[2] == 'i' && buf[3] == 'b')
        return 1; // /lib or /lib64

    // /etc/ld.so.cache (16 chars)
    if (slen >= 16 &&
        buf[0] == '/' && buf[1] == 'e' && buf[2] == 't' && buf[3] == 'c' && buf[4] == '/' &&
        buf[5] == 'l' && buf[6] == 'd' && buf[7] == '.' && buf[8] == 's' && buf[9] == 'o' &&
        buf[10] == '.' && buf[11] == 'c' && buf[12] == 'a' && buf[13] == 'c' && buf[14] == 'h' && buf[15] == 'e')
        return 1;

    // suffix-based noisy files (manual checks, no loops)
    if (slen >= 3 && buf[slen-3] == '.' && buf[slen-2] == 's' && buf[slen-1] == 'o')
        return 1; // .so
    if (slen >= 5 && buf[slen-5] == '.' && buf[slen-4] == 's' && buf[slen-3] == 'o' && buf[slen-2] == '.' && buf[slen-1] == '0')
        return 1; // .so.0
    if (slen >= 3 && buf[slen-3] == '.' && buf[slen-2] == 'm' && buf[slen-1] == 'o')
        return 1; // .mo
    if (slen >= 6 && buf[slen-6] == '.' && buf[slen-5] == 'c' && buf[slen-4] == 'a' && buf[slen-3] == 'c' && buf[slen-2] == 'h' && buf[slen-1] == 'e')
        return 1; // .cache
    if (slen >= 10 && buf[slen-10] == '.' && buf[slen-9] == 'g' && buf[slen-8] == 'i' && buf[slen-7] == 't' && buf[slen-6] == 'c' && buf[slen-5] == 'o' && buf[slen-4] == 'n' && buf[slen-3] == 'f' && buf[slen-2] == 'i' && buf[slen-1] == 'g')
        return 1; // .gitconfig

    return 0;
}

static __always_inline int trace_open_common(struct trace_event_raw_sys_enter *ctx, const char *fname)
{
    // filter noise before doing anything else
    if (is_noise(fname))
        return 0;

    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(comm, sizeof(comm));

    // check ignore list first — cheapest exit
    __u8 *ignored = bpf_map_lookup_elem(&ignored_commands, &comm);
    if (ignored)
        return 0;

    __u8 *allowed = bpf_map_lookup_elem(
        &allowed_commands,
        &comm
    );

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    __u32 pid  = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    if (!allowed) {
        // check if it is a child process of allowed command
        struct process_info *cp = bpf_map_lookup_elem(
            &child_root,
            &pid
        );
        if (!cp) {
            return 0;
        }
    }

    // Record entry time for latency calculation
    __u64 enter_time = bpf_ktime_get_ns();
    bpf_map_update_elem(&openat_start, &pid_tgid, &enter_time, BPF_ANY);

    struct openat_event *e = bpf_ringbuf_reserve(
        &events,
        sizeof(*e),
        0
    );

    if (!e)
        return 0;

    e->type = EVENT_OPENAT;
    e->pid = pid;
    e->tgid = tgid;
    e->timestamp_ns = enter_time;
    e->enter_time_ns = enter_time;

    __builtin_memcpy(e->comm, comm, sizeof(comm));

    if (bpf_probe_read_user_str(
            e->filename,
            sizeof(e->filename),
            fname) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    return trace_open_common(ctx, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_enter_open")
int trace_open(struct trace_event_raw_sys_enter *ctx)
{
    return trace_open_common(ctx, (const char *)ctx->args[0]);
}

SEC("tracepoint/syscalls/sys_enter_openat2")
int trace_openat2(struct trace_event_raw_sys_enter *ctx)
{
    return trace_open_common(ctx, (const char *)ctx->args[1]);
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx){
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // Look up the enter time
    __u64 *enter_time = bpf_map_lookup_elem(&openat_start, &pid_tgid);
    if (!enter_time)
        return 0;  // no matching enter event

    __u64 exit_time = bpf_ktime_get_ns();
    __u64 latency = exit_time - *enter_time;

    // Clean up the tracking entry
    bpf_map_delete_elem(&openat_start, &pid_tgid);

    // TODO: emit a completion event with latency and return value
    // For now we're emitting on enter, will refactor to emit on exit later

    return 0;
}

// handles process tree creation
SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx){
    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(comm, sizeof(comm));

    __u8 *allowed = bpf_map_lookup_elem(
        &allowed_commands,
        &comm
    );

    if (allowed){
        __u32 child_pid = ctx->child_pid;

        struct process_info info = {
            .rpid = ctx->parent_pid,
            .ppid = ctx->parent_pid,
        };

        __builtin_memcpy(info.fork_comm,
                        comm,
                        sizeof(comm));

        bpf_map_update_elem(
            &child_root,
            &child_pid,
            &info,
            BPF_ANY
        );
        return 0;
    }

    // check if it is a child process of allowed command
    __u32 ppid = ctx->parent_pid;
    struct process_info *cp = bpf_map_lookup_elem(
        &child_root,
        &ppid
    );

    if (!cp)
        return 0;

    struct process_info info = {
        .rpid = cp->rpid,
        .ppid = ctx->parent_pid,
    };

    __builtin_memcpy(info.fork_comm,
                    comm,
                    sizeof(comm));

    __u32 child_pid = ctx->child_pid;
    bpf_map_update_elem(
        &child_root,
        &child_pid,
        &info,
        BPF_ANY
    );
    return 0;
}

// it adds the child process name
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx){
    __u32 pid = (__u32)bpf_get_current_pid_tgid();

    struct process_info *info =
        bpf_map_lookup_elem(&child_root, &pid);

    if (!info)
        return 0;

    char comm[TASK_COMM_LEN];

    if (bpf_get_current_comm(comm, sizeof(comm)) < 0)
        return 0;

    __builtin_memcpy(
        info->current_comm,
        comm,
        sizeof(info->current_comm)
    );

    return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_exit *ctx)
{
    char comm[TASK_COMM_LEN];

    /* Use bpf_get_current_comm instead of reading ctx->comm directly to avoid
     * verifier complaints about dereferencing modified ctx pointers. */
    if (bpf_get_current_comm(comm, sizeof(comm)) < 0)
        return 0;

    __u32 pid = ctx->pid;

    __u8 *allowed = bpf_map_lookup_elem(&allowed_commands, &comm);
    
    // only track exits of allowed processes or their children
    if (!allowed){
        struct process_info *cp = bpf_map_lookup_elem(&child_root, &pid);
        if (!cp) 
            return 0;
    }

    // only care about thread group leader dying
    // ctx->group_dead = true means the whole process is dying
    // not just one thread — for crash detection this is what you want
    if (!ctx->group_dead)
        return 0;

    struct exit_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    e->type = EVENT_EXIT;

    // PIDs
    e->pid  = ctx->pid;
    e->tgid = BPF_CORE_READ(task, tgid);
    e->ppid = BPF_CORE_READ(task, real_parent, tgid);

    // timing
    e->start_time_ns = BPF_CORE_READ(task, start_time);
    e->exit_time_ns  = bpf_ktime_get_ns();

    // exit_code in task_struct encodes both signal and exit code
    // For normal exit: exit_code = (status << 8)
    // For signal death: exit_code = signal
    __u32 raw_exit = BPF_CORE_READ(task, exit_code);
    e->signal     = raw_exit & 0x7f;
    e->exit_code  = (raw_exit >> 8) & 0xff;

    e->group_dead = ctx->group_dead;

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";