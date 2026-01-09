// SPDX-License-Identifier: Dual BSD/GPL
// L4 Outbound TCP Connect Tracer
// Captures destination IPv4 address on tcp_v4_connect and publishes via ring buffer.
// Used for detecting outbound traffic from Pods (scale-from-zero trigger).

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../common/types.h"

// Legacy sockaddr structure for reading from userspace pointer
struct ipv4_sockaddr {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr;  // network byte order
};

// Ring buffer for L4 outbound events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);  // 256KB
} l4_events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_enter, struct sock *sk, struct sockaddr *uaddr)
{
    __u32 daddr = 0;
    struct l4_event *e;
    struct ipv4_sockaddr sa = {};

    // 1) Try to read destination from socket first
    if (sk) {
        daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    }

    // 2) If empty, try reading from sockaddr passed by caller
    if (!daddr && uaddr) {
        bpf_probe_read_kernel(&sa, sizeof(sa), uaddr);
        if (sa.sin_family == AF_INET) {
            daddr = sa.sin_addr;  // network byte order
        }
    }

    if (!daddr)
        return 0;

    e = bpf_ringbuf_reserve(&l4_events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->daddr = daddr;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
