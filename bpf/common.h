#ifndef EBPF_TOOL_COMMON_H
#define EBPF_TOOL_COMMON_H

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define COMM_LEN 16
#define ARG_LEN  128

#define EVT_EXEC   1
#define EVT_OPEN   2
#define EVT_SETUID 3

struct event {
    __u32 etype;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    char  comm[COMM_LEN];
    char  pcomm[COMM_LEN];
    char  arg[ARG_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20);
} events SEC(".maps");

static __always_inline void fill(struct event *e, __u32 etype) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    struct task_struct *p = BPF_CORE_READ(t, real_parent);

    e->etype = etype;
    e->pid   = bpf_get_current_pid_tgid() >> 32;
    e->uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->ppid  = BPF_CORE_READ(p, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    BPF_CORE_READ_STR_INTO(&e->pcomm, p, comm);
}

#endif
