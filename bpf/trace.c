//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

// map: child_pid → parent_pid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);    // child pid
    __type(value, u32);  // parent pid
} child_parent SEC(".maps");

// map: comm string → 1 (exists = track this command)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u8[16]);   // comm is max 16 bytes in Linux
    __type(value, u32);    // just a flag, 1 = track
} filter_root_comms SEC(".maps");

// map: parent pid -> root pid
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, u32);   // parent pid
    __type(value, u32);    // root pid
} parent_root SEC(".maps");

struct event {
    u32 ppid;
    u32 pid;
    u32 rpid;
    char child_comm[16];
} __attribute__((packed));

// Ring buffer map — the channel between kernel and userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24); // 16MB
} events SEC(".maps");

SEC("tracepoint/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{   
    u8 comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    // check if this command is in our filter map
    u32 *val = bpf_map_lookup_elem(&filter_root_comms, comm);
    if (!val){
        // check for parent comms
        u32 ppid = ctx->parent_pid;
        u32 *val = bpf_map_lookup_elem(&child_parent, &ppid);

        if (!val) return 0;

        // get it's root pid from it's parent root pid
        u32 *rpid = bpf_map_lookup_elem(&parent_root, &ppid);

        // set the current process root pid as it's parent root pid
        u32 pid = ctx->child_pid;
        bpf_map_update_elem(&parent_root, pid, rpid, BPF_ANY);
        // remove the parent from child_parent map
        // bpf_map_delete_elem(&child_parent, &ppid);
    }

    u32 parent_pid = ctx->parent_pid;
    u32 child_pid  = ctx->child_pid;

    // record the relationship
    bpf_map_update_elem(&child_parent, &child_pid, &parent_pid, BPF_ANY);

    // in parent_root initial parent and root will be same
    bpf_map_update_elem(&parent_root, &parent_pid, &parent_pid, BPF_ANY);
    return 0;
}

SEC("tracepoint/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;

    // look up who spawned this process
    u32 *parent = bpf_map_lookup_elem(&child_parent, &pid);
    if (parent) {
        // now you have pid + parent_pid + binary path all together
        u32 *rpid = bpf_map_lookup_elem(&parent_root, &pid);
        
        struct event *e;
        e->ppid = *parent;
        e->pid = pid;
        e->rpid = *rpid;
        bpf_get_current_comm(e->child_comm, sizeof(e->child_comm));
    }
}