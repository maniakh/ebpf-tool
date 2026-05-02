#include "common.h"

SEC("tp/syscalls/sys_enter_execve")
int handle_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill(e, EVT_EXEC);
    bpf_probe_read_user_str(&e->arg, sizeof(e->arg), (const char *)ctx->args[0]);
    bpf_ringbuf_submit(e, 0);
    return 0;
}
