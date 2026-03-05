// SPDX-License-Identifier: Dual BSD/GPL
// L7 Inbound HTTP Request Tracer (L7 수신 HTTP 요청 추적기) - 단순화 버전

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../common/types.h"

// ============================================================================
// Maps
// ============================================================================

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ACTIVE_ACCEPT);
    __type(key, __u64);
    __type(value, struct accept_args_t);
} active_accept_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ACTIVE_READ);
    __type(key, __u64);
    __type(value, struct read_args_t);
} active_read_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOCKET_INFO);
    __type(key, __u64);
    __type(value, struct socket_info_t);
} socket_info_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, HTTP_RINGBUF_SIZE);
} http_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ACTIVE_ACCEPT);
    __type(key, __u64);
    __type(value, struct pending_sock_info_t);
} pending_sock_info SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// HTTP 요청 여부만 상수로 확인 (검증기 에러 없음)
static __always_inline bool is_http_request(const char *buf)
{
    __u32 first4 = 0;
    if (bpf_probe_read_user(&first4, sizeof(first4), buf) < 0) {
        return false;
    }

    if (first4 == HTTP_GET_MAGIC)  return true;
    if (first4 == HTTP_POST_MAGIC) return true;
    if (first4 == HTTP_PUT_MAGIC)  return true;
    if (first4 == HTTP_DELE_MAGIC) return true;
    if (first4 == HTTP_HEAD_MAGIC) return true;
    if (first4 == HTTP_PATC_MAGIC) return true;
    if (first4 == HTTP_OPTI_MAGIC) return true;

    return false;
}

// ============================================================================
// Tracepoints & Kprobes
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct accept_args_t args = {};
    args.sockfd = (int)ctx->args[0];
    args.addr = (__u64)ctx->args[1];
    bpf_map_update_elem(&active_accept_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->ret;
    if (fd < 0) {
        bpf_map_delete_elem(&active_accept_args, &pid_tgid);
        bpf_map_delete_elem(&pending_sock_info, &pid_tgid);
        return 0;
    }

    struct accept_args_t *args = bpf_map_lookup_elem(&active_accept_args, &pid_tgid);
    if (!args) {
        bpf_map_delete_elem(&pending_sock_info, &pid_tgid);
        return 0;
    }

    struct socket_info_t info = {};
    info.accept_time = bpf_ktime_get_ns();
    struct pending_sock_info_t *pending = bpf_map_lookup_elem(&pending_sock_info, &pid_tgid);
    if (pending) {
        info.local_addr = pending->local_addr;
        info.local_port = pending->local_port;
        info.client_addr = pending->client_addr;
        info.client_port = pending->client_port;
        bpf_map_delete_elem(&pending_sock_info, &pid_tgid);
    }

    if (info.client_addr == 0 && args->addr) {
        struct sockaddr_in client_addr = {};
        if (bpf_probe_read_user(&client_addr, sizeof(client_addr), (void *)args->addr) == 0) {
            if (client_addr.sin_family == AF_INET) {
                info.client_addr = client_addr.sin_addr.s_addr;
                info.client_port = client_addr.sin_port;
            }
        }
    }

    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) + (__u64)fd;
    bpf_map_update_elem(&socket_info_map, &sock_key, &info, BPF_ANY);
    bpf_map_delete_elem(&active_accept_args, &pid_tgid);
    return 0;
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept, struct sock *sk)
{
    if (!sk) return 0;
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    struct pending_sock_info_t pending = {};
    pending.local_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    pending.local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    pending.client_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    pending.client_port = BPF_CORE_READ(sk, __sk_common.skc_dport);
    bpf_map_update_elem(&pending_sock_info, &pid_tgid, &pending, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) + (__u64)fd;
    if (!bpf_map_lookup_elem(&socket_info_map, &sock_key)) return 0;

    struct read_args_t args = {};
    args.fd = fd;
    args.buf = (__u64)ctx->args[1];
    bpf_map_update_elem(&active_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __s64 bytes_read = ctx->ret;
    if (bytes_read <= 0) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;
    }

    struct read_args_t *args = bpf_map_lookup_elem(&active_read_args, &pid_tgid);
    if (!args) return 0;

    // HTTP 여부만 확인
    if (!is_http_request((const char *)args->buf)) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;
    }

    struct http_event *e = bpf_ringbuf_reserve(&http_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;
    }

    // 기본 정보 채우기
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) + (__u64)args->fd;
    struct socket_info_t *sock = bpf_map_lookup_elem(&socket_info_map, &sock_key);
    if (sock) {
        e->saddr = sock->client_addr;
        e->sport = sock->client_port;
        e->daddr = sock->local_addr;
        e->dport = bpf_htons(sock->local_port);
    } else {
        e->saddr = 0; e->sport = 0; e->daddr = 0; e->dport = 0;
    }
    e->pid = (uint32_t)(pid_tgid >> 32);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 핵심: Raw Payload 복사 (파싱 없이 고정 크기 한 번만 읽기)
    // bytes_read가 MAX_PAYLOAD_LEN보다 작아도 bpf_probe_read_user가 안전하게 처리함
    bpf_probe_read_user(e->payload, MAX_PAYLOAD_LEN, (const char *)args->buf);
    e->payload_len = bytes_read < MAX_PAYLOAD_LEN ? (__u32)bytes_read : MAX_PAYLOAD_LEN;

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&active_read_args, &pid_tgid);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_close")
int sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) + (__u64)fd;
    bpf_map_delete_elem(&socket_info_map, &sock_key);
    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
