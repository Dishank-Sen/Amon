// go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event {
    __u32 pid;
    __u32 tgid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};

struct process_info {
    u32 ppid;
    u32 rpid;
    char fork_comm[16];
    char current_comm[16];
};

// map for allowed command to be filtered out
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, __u8);
} allowed_commands SEC(".maps");

// map: child -> root
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct process_info);
} child_root SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx)
{
    char comm[TASK_COMM_LEN];

    bpf_get_current_comm(comm, sizeof(comm));

    __u8 *allowed = bpf_map_lookup_elem(
        &allowed_commands,
        &comm
    );

    if (!allowed)
        return 0;   // process not in filter list

    struct event *e = bpf_ringbuf_reserve(
        &events,
        sizeof(*e),
        0
    );

    if (!e)
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    e->pid = (__u32)pid_tgid;
    e->tgid = (__u32)(pid_tgid >> 32);

    __builtin_memcpy(e->comm, comm, sizeof(comm));

    if (bpf_probe_read_user_str(
            e->filename,
            sizeof(e->filename),
            (const char *)ctx->args[1]) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    bpf_ringbuf_submit(e, 0);

    return 0;
}

SEC("tracepoint/syscalls/sys_exit_openat")
int trace_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
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
    struct process_info *cp = bpf_map_lookup_elem(
        &child_root,
        &ctx->parent_pid
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

    bpf_map_update_elem(
        &child_root,
        &ctx->child_pid,
        &info,
        BPF_ANY
    );
    return 0;
}

// it adds the child process name
SEC("tracepoint/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

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

char LICENSE[] SEC("license") = "GPL";