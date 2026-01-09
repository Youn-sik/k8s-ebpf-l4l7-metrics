#!/usr/bin/env bash
# Generate vmlinux.h and bpf2go bindings for L4 sender and L7 receiver eBPF programs.
# Must be run on a Linux host with BTF-enabled kernel (e.g., /sys/kernel/btf/vmlinux present),
# clang/llvm installed, and bpftool available in PATH.
#
# Usage:
#   ARCH=x86 ./gen_bpf.sh        # for x86_64 nodes
#   ARCH=arm64 ./gen_bpf.sh      # for arm64 nodes
#   ARCH=x86 ./gen_bpf.sh l4     # L4 only
#   ARCH=x86 ./gen_bpf.sh l7     # L7 only
#
# Outputs:
#   ebpf/bpf/vmlinux.h
#   ebpf/artifacts/<arch>/l4_sender_bpfel.go, l4_sender_bpfeb.go
#   ebpf/artifacts/<arch>/l7_receiver_bpfel.go, l7_receiver_bpfeb.go

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
BPF_DIR="${SCRIPT_DIR}/bpf"
BUILD_TARGET="${1:-all}"  # all, l4, l7

ARCH_INPUT="${ARCH:-}"
if [[ -z "${ARCH_INPUT}" ]]; then
  ARCH_INPUT="$(uname -m)"
fi

# Artifact directory name mapping
case "${ARCH_INPUT}" in
  x86_64|amd64|x86|i386|i686)
    ARTIFACT_ARCH="amd64"
    ;;
  arm64|aarch64)
    ARTIFACT_ARCH="arm64"
    ;;
  *)
    ARTIFACT_ARCH="${ARCH_INPUT}"
    ;;
esac

# bpf2go/clang target arch mapping
case "${ARCH_INPUT}" in
  x86_64|amd64|x86|i386|i686)
    TARGET_ARCH="x86"
    ;;
  arm64|aarch64)
    TARGET_ARCH="arm64"
    ;;
  *)
    TARGET_ARCH="${ARCH_INPUT}"
    ;;
esac

PKG="${GOPACKAGE:-ebpf}"

# Validate environment
if [[ "$(uname -s)" != "Linux" ]]; then
  echo "This script must run on Linux with BTF-enabled kernel." >&2
  exit 1
fi

if ! command -v bpftool >/dev/null 2>&1; then
  echo "bpftool not found in PATH; install it first." >&2
  exit 1
fi

if [[ ! -f "/sys/kernel/btf/vmlinux" ]]; then
  echo "/sys/kernel/btf/vmlinux not found; ensure kernel was built with BTF." >&2
  exit 1
fi

if ! command -v bpf2go >/dev/null 2>&1; then
  echo "bpf2go not found; install via: go install github.com/cilium/ebpf/cmd/bpf2go@latest" >&2
  exit 1
fi

# Create artifact directory
ART_DIR="${SCRIPT_DIR}/artifacts/${ARTIFACT_ARCH}"
mkdir -p "${ART_DIR}"

# Step 1: Generate vmlinux.h
echo "[1/3] Dumping vmlinux.h from kernel BTF..."
bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${BPF_DIR}/vmlinux.h"
cp "${BPF_DIR}/vmlinux.h" "${ART_DIR}/"

# Common CFLAGS
CFLAGS="-g -O2 -D__TARGET_ARCH_${TARGET_ARCH}"
INCLUDE_FLAGS="-I${BPF_DIR}"

# Step 2: Build L4 Sender (tcp_connect)
build_l4() {
  echo "[2/3] Building L4 Sender (tcp_connect)..."
  cd "${BPF_DIR}/l4_sender"

  bpf2go -cc clang -target bpfel -go-package "${PKG}" -cflags "${CFLAGS}" \
    L4Sender tcp_connect.c -- ${INCLUDE_FLAGS}
  bpf2go -cc clang -target bpfeb -go-package "${PKG}" -cflags "${CFLAGS}" \
    L4Sender tcp_connect.c -- ${INCLUDE_FLAGS}

  # Copy artifacts
  cp l4sender_bpfel.go l4sender_bpfeb.go "${ART_DIR}/"
  cp l4sender_bpfel.o l4sender_bpfeb.o "${ART_DIR}/"

  # Cleanup working directory
  rm -f l4sender_bpfel.go l4sender_bpfeb.go l4sender_bpfel.o l4sender_bpfeb.o

  echo "  L4 Sender artifacts generated."
}

# Step 3: Build L7 Receiver (http_trace)
build_l7() {
  echo "[3/3] Building L7 Receiver (http_trace)..."
  cd "${BPF_DIR}/l7_receiver"

  bpf2go -cc clang -target bpfel -go-package "${PKG}" -cflags "${CFLAGS}" \
    L7Receiver http_trace.c -- ${INCLUDE_FLAGS}
  bpf2go -cc clang -target bpfeb -go-package "${PKG}" -cflags "${CFLAGS}" \
    L7Receiver http_trace.c -- ${INCLUDE_FLAGS}

  # Copy artifacts
  cp l7receiver_bpfel.go l7receiver_bpfeb.go "${ART_DIR}/"
  cp l7receiver_bpfel.o l7receiver_bpfeb.o "${ART_DIR}/"

  # Cleanup working directory
  rm -f l7receiver_bpfel.go l7receiver_bpfeb.go l7receiver_bpfel.o l7receiver_bpfeb.o

  echo "  L7 Receiver artifacts generated."
}

# Execute based on target
case "${BUILD_TARGET}" in
  l4)
    build_l4
    ;;
  l7)
    build_l7
    ;;
  all)
    build_l4
    build_l7
    ;;
  *)
    echo "Unknown target: ${BUILD_TARGET}. Use 'all', 'l4', or 'l7'." >&2
    exit 1
    ;;
esac

echo ""
echo "Done. Generated artifacts under ${ART_DIR}:"
ls -la "${ART_DIR}"
