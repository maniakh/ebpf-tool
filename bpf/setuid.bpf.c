#include "common.h"

SEC("tp/syscalls/sys_enter_setuid")
int handle_setuid(struct trace_event_raw_sys_enter *ctx) {
    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    fill(e, EVT_SETUID);
    e->arg[0] = 0;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
