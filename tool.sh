#!/usr/bin/env bash
set -euo pipefail

# findo single-entry launcher
# Works both inside repo and via: curl|bash

REPO_URL="https://github.com/maniakh/ebpf-tool.git"

need() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing dependency: $1"
    exit 1
  }
}

if [ "$(id -u)" -eq 0 ]; then
  SUDO=""
else
  SUDO="sudo"
fi

need go
need clang
need bpftool

# If script is executed outside repo (curl|bash), clone to temp dir.
if [ ! -f "main.go" ] || [ ! -d "bpf" ]; then
  need git
  WORKDIR="${TMPDIR:-/tmp}/findo-$(date +%s)"
  git clone --depth 1 "$REPO_URL" "$WORKDIR"
  cd "$WORKDIR"
fi

mkdir -p bpf

if [ ! -f "bpf/vmlinux.h" ]; then
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
fi

go mod tidy
go generate .
exec $SUDO go run .
