#!/bin/bash
# Quick test: load eBPF programs and verify they attach
# Run on server with sudo

set -euo pipefail

BPF_OBJ="target/bpfel-unknown-none/release/innerwarden-ebpf"

if [ ! -f "$BPF_OBJ" ]; then
  echo "eBPF binary not found. Run:"
  echo "  cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release"
  exit 1
fi

echo "Testing eBPF program load..."
echo "Binary: $BPF_OBJ ($(stat -c%s "$BPF_OBJ") bytes)"
echo ""

# Use bpftool to verify the ELF contains valid programs
if command -v bpftool >/dev/null 2>&1; then
  echo "Programs in ELF:"
  bpftool prog load "$BPF_OBJ" /sys/fs/bpf/innerwarden_test 2>&1 && \
    echo "  ✅ Loaded successfully" && \
    bpftool prog show pinned /sys/fs/bpf/innerwarden_test && \
    rm /sys/fs/bpf/innerwarden_test || \
    echo "  ❌ Load failed (may need sudo or different program section)"
else
  echo "bpftool not installed — install with: sudo apt install linux-tools-common"
fi
