// SPDX-License-Identifier: GPL-2.0
// split layout: common + per-hook files
#include "common.h"
#include "execve.bpf.c"
#include "openat.bpf.c"
#include "setuid.bpf.c"

char LICENSE[] SEC("license") = "GPL";
