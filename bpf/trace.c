// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

// Event type constants
#define EVENT_OPENAT  1
#define EVENT_EXIT    2
#define EVENT_CONNECT 3
#define EVENT_SIGNAL  4  // Signal delivery with stack trace
#define AF_INET  2

// Maximum stack depth to capture
#define MAX_STACK_DEPTH 20

// Signal context for crash forensics - define BEFORE exit_event
struct signal_info {
    __u64 fault_addr;    // si_addr for SIGSEGV/SIGBUS
    __s32 si_code;       // signal code (SEGV_MAPERR, SEGV_ACCERR, etc)
    __u32 _pad;
} __attribute__((packed));

// All events start with type field for Go dispatcher
struct openat_event {
    __u32 type;      // EVENT_OPENAT
    __u32 pid;
    __u32 tgid;
    __u64 timestamp_ns;
    __u64 latency_ns;
    __s64 ret;       // return value: fd on success, -errno on error
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
    __u8 _pad[3];

    struct signal_info sig_info;

    char comm[TASK_COMM_LEN];
} __attribute__((packed));

struct process_info {
    u32 ppid;
    u32 rpid;
    char fork_comm[TASK_COMM_LEN];
    char current_comm[TASK_COMM_LEN];
} __attribute__((packed));

struct connect_data {
    __u32 pid;
    __u64 timestamp;
    __u16 family;
    __u16 dport;     // destination port
    __u32 daddr;     // destination IP (IPv4)
} __attribute__((packed));

struct connect_event {
    __u32 type;
    __u32 pid;
    __u64 timestamp;
    __u64 latency;
    __s64 ret;
    __u16 family;
    __u16 dport;     // destination port
    __u32 daddr;     // destination IP (IPv4)
} __attribute__((packed));

// Signal delivery event with stack trace
struct signal_event {
    __u32 type;          // EVENT_SIGNAL
    __u32 pid;
    __u32 tgid;
    __u32 signal;        // Signal number (11=SIGSEGV, etc)

    __u64 timestamp_ns;
    __u64 fault_addr;    // si_addr from siginfo_t
    __s32 si_code;       // SEGV_MAPERR, SEGV_ACCERR, etc
    __s32 stack_id;      // ID in stack map (-1 if capture failed)

    char comm[TASK_COMM_LEN];
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct connect_data);
} connect_start SEC(".maps");

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

// map: track openat enter info for latency and context
// key: (pid << 32) | tid to handle multi-threaded processes
struct openat_info {
    __u64 enter_time;
    char filename[256];
    char comm[TASK_COMM_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u64);
    __type(value, struct openat_info);
} openat_start SEC(".maps");

// Single unified ring buffer for all events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

// Stack trace map - stores user-space stack traces
// Key is stack_id, value is array of instruction pointers
struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, 1024);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, MAX_STACK_DEPTH * sizeof(__u64));
} stack_traces SEC(".maps");

static __always_inline int is_noise(const char *filename)
{
    char buf[64];
    int len = bpf_probe_read_user_str(buf, sizeof(buf), filename);
    if (len <= 0)
        return 1; // unreadable is noisy

    int slen = len - 1; // excluding NUL

    // common noisy prefixes - ONLY truly useless files
    if (slen >= 4 && buf[0] == '/' && buf[1] == 'd' && buf[2] == 'e' && buf[3] == 'v')
        return 1;  // /dev/* - never useful
    if (slen >= 5 && buf[0] == '/' && buf[1] == 'p' && buf[2] == 'r' && buf[3] == 'o' && buf[4] == 'c')
        return 1;  // /proc/* - never useful
    if (slen >= 4 && buf[0] == '/' && buf[1] == 's' && buf[2] == 'y' && buf[3] == 's')
        return 1;  // /sys/* - never useful

    // REMOVED: /usr/* and /lib/* filters
    // These are important for startup/crash context

    // REMOVED: .so, ld.so.cache, .mo filters
    // These are important for understanding library loads and startup

    // Keep only truly useless filters
    if (slen >= 10 && buf[slen-10] == '.' && buf[slen-9] == 'g' && buf[slen-8] == 'i' && buf[slen-7] == 't' && buf[slen-6] == 'c' && buf[slen-5] == 'o' && buf[slen-4] == 'n' && buf[slen-3] == 'f' && buf[slen-2] == 'i' && buf[slen-1] == 'g')
        return 1; // .gitconfig - never relevant to crashes

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

    // Store entry info for later (will emit event on exit with return value)
    struct openat_info info = {};
    info.enter_time = bpf_ktime_get_ns();
    __builtin_memcpy(info.comm, comm, sizeof(info.comm));

    if (bpf_probe_read_user_str(info.filename, sizeof(info.filename), fname) < 0) {
        return 0;
    }

    bpf_map_update_elem(&openat_start, &pid_tgid, &info, BPF_ANY);

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

    // Look up the enter info
    struct openat_info *info = bpf_map_lookup_elem(&openat_start, &pid_tgid);
    if (!info)
        return 0;  // no matching enter event

    __u64 exit_time = bpf_ktime_get_ns();
    __u64 latency = exit_time - info->enter_time;
    __s64 ret = ctx->ret;  // return value: fd >= 0 on success, -errno on error

    // Emit complete event with return value and latency
    struct openat_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&openat_start, &pid_tgid);
        return 0;
    }

    __u32 pid  = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    e->type = EVENT_OPENAT;
    e->pid = pid;
    e->tgid = tgid;
    e->timestamp_ns = exit_time;
    e->latency_ns = latency;
    e->ret = ret;

    __builtin_memcpy(e->comm, info->comm, sizeof(e->comm));
    __builtin_memcpy(e->filename, info->filename, sizeof(e->filename));

    bpf_ringbuf_submit(e, 0);

    // Clean up the tracking entry
    bpf_map_delete_elem(&openat_start, &pid_tgid);

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

// Store signal info when signal is generated (before delivery)
struct signal_context {
    __u64 fault_addr;
    __s32 si_code;
    __u32 signal;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);  // tgid
    __type(value, struct signal_context);
} pending_signals SEC(".maps");

// Kprobe on force_sig_fault - captures SIGSEGV/SIGBUS with fault address
// This runs when the kernel generates the signal (at fault time)
// force_sig_fault signature: int force_sig_fault(int sig, int code, void __user *addr)
SEC("kprobe/force_sig_fault")
int probe_force_sig_fault(struct pt_regs *ctx)
{
    // Read arguments from registers (x86-64 calling convention)
    int sig = (int)PT_REGS_PARM1(ctx);
    int code = (int)PT_REGS_PARM2(ctx);
    void *addr = (void *)PT_REGS_PARM3(ctx);

    // Only care about memory fault signals
    if (sig != 11 && sig != 7)  // SIGSEGV, SIGBUS
        return 0;

    __u32 tgid = bpf_get_current_pid_tgid() >> 32;

    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    // Check if tracked
    __u8 *allowed = bpf_map_lookup_elem(&allowed_commands, &comm);
    if (!allowed) {
        struct process_info *cp = bpf_map_lookup_elem(&child_root, &tgid);
        if (!cp)
            return 0;
    }

    // Store signal context for later retrieval
    struct signal_context sig_ctx = {
        .fault_addr = (__u64)addr,
        .si_code = code,
        .signal = sig,
    };

    bpf_map_update_elem(&pending_signals, &tgid, &sig_ctx, BPF_ANY);
    return 0;
}

// Signal delivery tracepoint - captures crash with stack trace
// This runs when signal is actually delivered to userspace
SEC("tracepoint/signal/signal_deliver")
int handle_signal_deliver(struct trace_event_raw_signal_deliver *ctx)
{
    __u32 sig = ctx->sig;

    // Only capture crash signals (not SIGTERM, SIGKILL, etc)
    if (sig != 11 && sig != 6 && sig != 7 && sig != 4 && sig != 8)
        return 0;  // Not a crash signal

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid  = (__u32)pid_tgid;
    __u32 tgid = pid_tgid >> 32;

    char comm[TASK_COMM_LEN];
    if (bpf_get_current_comm(comm, sizeof(comm)) < 0)
        return 0;

    // Check if this is an allowed/tracked process
    __u8 *allowed = bpf_map_lookup_elem(&allowed_commands, &comm);
    if (!allowed) {
        struct process_info *cp = bpf_map_lookup_elem(&child_root, &tgid);
        if (!cp)
            return 0;  // Not tracked
    }

    // Capture user-space stack trace - THIS IS THE KEY
    __s32 stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);

    // Retrieve fault address from pending_signals map (stored by kprobe)
    __u64 fault_addr = 0;
    __s32 si_code = 0;

    struct signal_context *sig_ctx = bpf_map_lookup_elem(&pending_signals, &tgid);
    if (sig_ctx && sig_ctx->signal == sig) {
        fault_addr = sig_ctx->fault_addr;
        si_code = sig_ctx->si_code;
        bpf_map_delete_elem(&pending_signals, &tgid);  // Clean up
    }

    // Emit signal event with stack trace
    struct signal_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->type = EVENT_SIGNAL;
    e->pid = pid;
    e->tgid = tgid;
    e->signal = sig;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->fault_addr = fault_addr;
    e->si_code = si_code;
    e->stack_id = stack_id;

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
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

    // Capture signal info for crash forensics
    // Note: Directly reading siginfo from task_struct is tricky due to kernel API changes
    // We'll rely on userspace analysis of /proc/pid/maps and heuristics
    // The signal number itself provides significant information
    e->sig_info.fault_addr = 0;
    e->sig_info.si_code = 0;

    // TODO: Future enhancement - use signal tracepoint instead of exit tracepoint
    // to capture siginfo_t directly when the signal is delivered

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int handle_connect_enter(struct trace_event_raw_sys_enter *ctx)
{
    // args[0] = fd
    // args[1] = pointer to sockaddr struct (userspace)
    // args[2] = length of sockaddr

    struct sockaddr_in addr;

    // read the sockaddr from userspace — NOT a direct dereference
    if (bpf_probe_read_user(&addr, sizeof(addr),
            (void *)ctx->args[1]) < 0)
        return 0;

    // only handle IPv4 for now — ignore unix sockets, IPv6 etc
    if (addr.sin_family != AF_INET)
        return 0;

    // store entry data in hash map for exit handler to pick up
    struct connect_data data = {};
    data.pid       = bpf_get_current_pid_tgid() >> 32;
    data.timestamp = bpf_ktime_get_ns();
    data.family    = addr.sin_family;
    data.dport     = __builtin_bswap16(addr.sin_port);  // convert big-endian to little-endian
    data.daddr     = addr.sin_addr.s_addr;

    bpf_map_update_elem(&connect_start, &data.pid, &data, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_connect")
int handle_connect_exit(struct trace_event_raw_sys_exit *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // look up entry data
    struct connect_data *data = bpf_map_lookup_elem(&connect_start, &pid);
    if (!data)
        return 0;

    // check ignored/allowed — same pattern as your file hooks
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));

    __u8 *ignored = bpf_map_lookup_elem(&ignored_commands, &comm);
    if (ignored) {
        bpf_map_delete_elem(&connect_start, &pid);
        return 0;
    }

    __u8 *allowed = bpf_map_lookup_elem(&allowed_commands, &comm);
    if (!allowed) {
        struct process_info *cp = bpf_map_lookup_elem(&child_root, &pid);
        if (!cp){
            bpf_map_delete_elem(&connect_start, &pid);
            return 0;
        }
    }

    // build the event
    struct connect_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&connect_start, &pid);
        return 0;
    }

    __u64 exit_time = bpf_ktime_get_ns();

    e->type      = EVENT_CONNECT;
    e->pid       = pid;
    e->timestamp = exit_time;          // FIX: set actual timestamp
    e->latency   = exit_time - data->timestamp;
    e->ret       = ctx->ret;
    e->dport     = data->dport;
    e->daddr     = data->daddr;
    e->family    = data->family;

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&connect_start, &pid);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";