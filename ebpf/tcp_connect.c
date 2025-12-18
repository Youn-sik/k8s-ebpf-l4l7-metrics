// eBPF program: capture destination IPv4 address on tcp_v4_connect and publish via ring buffer.
// NOTE: Requires vmlinux.h generated for target kernel (bpf2go -target bpfel/bpfeb).

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

/* 최소 정의만 사용해 커널 헤더 중복을 피한다. */
#ifndef AF_INET
#define AF_INET 2
#endif

struct ipv4_sockaddr {
    __u16 sin_family;
    __u16 sin_port;
    __u32 sin_addr; // network byte order
};

struct event {
    __u32 daddr; // Destination IPv4 (network byte order) -> convert in Go using binary.BigEndian
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_enter, struct sock *sk, struct sockaddr *uaddr)
{
    __u32 daddr;
    struct event *e;
    struct ipv4_sockaddr sa = {};

    /* 1) 소켓에 기록된 목적지가 있으면 우선 사용한다. */
    if (sk)
        daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);

    /* 2) 비어 있으면 호출자가 넘긴 sockaddr에서 읽어본다. */
    if (!daddr && uaddr) {
        bpf_probe_read_kernel(&sa, sizeof(sa), uaddr);
        if (sa.sin_family == AF_INET) {
            daddr = sa.sin_addr; // network byte order
        }
    }
    if (!daddr)
        return 0;

    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->daddr = daddr;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
