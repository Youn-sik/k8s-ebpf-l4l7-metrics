// SPDX-License-Identifier: Dual BSD/GPL
// L7 Inbound HTTP Request Tracer
// Captures HTTP requests to Pods via sys_enter/exit_accept4 and sys_enter/exit_read.
// Used for detecting inbound HTTP traffic with method and path extraction.

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "../common/types.h"

// ============================================================================
// Maps
// ============================================================================

// Store accept() arguments between sys_enter and sys_exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ACTIVE_ACCEPT);
    __type(key, __u64);                    // pid_tgid
    __type(value, struct accept_args_t);
} active_accept_args SEC(".maps");

// Store read() arguments between sys_enter and sys_exit
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ACTIVE_READ);
    __type(key, __u64);                    // pid_tgid
    __type(value, struct read_args_t);
} active_read_args SEC(".maps");

// Map FD to socket info (client IP/port from accept)
// Key: (pid_tgid & 0xFFFFFFFF00000000) | fd
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_SOCKET_INFO);
    __type(key, __u64);
    __type(value, struct socket_info_t);
} socket_info_map SEC(".maps");

// Ring buffer for HTTP events to userspace
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, HTTP_RINGBUF_SIZE);
} http_events SEC(".maps");

// ============================================================================
// Helper Functions
// ============================================================================

// Check if buffer starts with HTTP request method
static __always_inline bool is_http_request(const char *buf)
{
    __u32 first4;
    bpf_probe_read_user(&first4, sizeof(first4), buf);

    // Compare against known HTTP method magic numbers (little-endian)
    if (first4 == HTTP_GET_MAGIC)  return true;  // "GET "
    if (first4 == HTTP_POST_MAGIC) return true;  // "POST"
    if (first4 == HTTP_PUT_MAGIC)  return true;  // "PUT "
    if (first4 == HTTP_DELE_MAGIC) return true;  // "DELE"
    if (first4 == HTTP_HEAD_MAGIC) return true;  // "HEAD"
    if (first4 == HTTP_PATC_MAGIC) return true;  // "PATC"
    if (first4 == HTTP_OPTI_MAGIC) return true;  // "OPTI"

    return false;
}

// Parse HTTP method and path from request buffer
// Path is limited to MAX_PATH_DEPTH levels (e.g., /api/users/*)
static __always_inline void parse_http_request(
    const char *buf,
    __s64 len,
    char *method_out,
    char *path_out)
{
    char local_buf[128];
    int read_len = len > 127 ? 127 : len;

    // Read request line into local buffer
    if (bpf_probe_read_user(local_buf, read_len, buf) < 0) {
        method_out[0] = '\0';
        path_out[0] = '\0';
        return;
    }
    local_buf[read_len] = '\0';

    // Extract method (until first space)
    int i = 0;
    #pragma unroll
    for (; i < 7 && i < read_len; i++) {
        if (local_buf[i] == ' ') break;
        method_out[i] = local_buf[i];
    }
    method_out[i] = '\0';

    // Skip space to find path start
    int path_start = i + 1;
    if (path_start >= read_len) {
        path_out[0] = '\0';
        return;
    }

    // Extract path with depth limit
    int depth = 0;
    int path_idx = 0;

    #pragma unroll
    for (int j = path_start; j < read_len && path_idx < (MAX_PATH_LEN - 2); j++) {
        char c = local_buf[j];

        // End of path: space, query string, or fragment
        if (c == ' ' || c == '?' || c == '#' || c == '\r' || c == '\n') {
            break;
        }

        // Count depth on slash
        if (c == '/') {
            depth++;
            if (depth > MAX_PATH_DEPTH) {
                // Truncate with wildcard
                path_out[path_idx++] = '/';
                path_out[path_idx++] = '*';
                break;
            }
        }

        path_out[path_idx++] = c;
    }
    path_out[path_idx] = '\0';
}

// ============================================================================
// Tracepoints: accept4 syscall
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct accept_args_t args = {};
    args.sockfd = (int)ctx->args[0];
    args.addr = (struct sockaddr *)ctx->args[1];

    bpf_map_update_elem(&active_accept_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->ret;

    // accept failed
    if (fd < 0) {
        bpf_map_delete_elem(&active_accept_args, &pid_tgid);
        return 0;
    }

    struct accept_args_t *args = bpf_map_lookup_elem(&active_accept_args, &pid_tgid);
    if (!args) {
        return 0;
    }

    // Create socket info entry
    struct socket_info_t info = {};
    info.accept_time = bpf_ktime_get_ns();

    // Read client address if available
    if (args->addr) {
        struct sockaddr_in client_addr = {};
        if (bpf_probe_read_user(&client_addr, sizeof(client_addr), args->addr) == 0) {
            if (client_addr.sin_family == AF_INET) {
                info.client_addr = client_addr.sin_addr.s_addr;
                info.client_port = client_addr.sin_port;
            }
        }
    }

    // Key: high 32 bits = pid, low 32 bits = fd
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) | (__u64)fd;
    bpf_map_update_elem(&socket_info_map, &sock_key, &info, BPF_ANY);

    bpf_map_delete_elem(&active_accept_args, &pid_tgid);
    return 0;
}

// ============================================================================
// Tracepoints: read syscall
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];

    // Check if this fd is a tracked socket
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) | (__u64)fd;
    if (!bpf_map_lookup_elem(&socket_info_map, &sock_key)) {
        return 0;  // Not a tracked socket, ignore
    }

    struct read_args_t args = {};
    args.fd = fd;
    args.buf = (char *)ctx->args[1];

    bpf_map_update_elem(&active_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __s64 bytes_read = ctx->ret;

    // Read failed or no data
    if (bytes_read <= 0) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;
    }

    struct read_args_t *args = bpf_map_lookup_elem(&active_read_args, &pid_tgid);
    if (!args) {
        return 0;
    }

    // Check if this looks like an HTTP request
    if (!is_http_request(args->buf)) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;
    }

    // Reserve space in ring buffer
    struct http_event *e = bpf_ringbuf_reserve(&http_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;
    }

    // Fill event with socket info
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) | (__u64)args->fd;
    struct socket_info_t *sock = bpf_map_lookup_elem(&socket_info_map, &sock_key);
    if (sock) {
        e->saddr = sock->client_addr;
        e->sport = sock->client_port;
    } else {
        e->saddr = 0;
        e->sport = 0;
    }

    // Local address/port would require additional lookup (not implemented)
    e->daddr = 0;
    e->dport = 0;

    // Process info
    e->pid = pid_tgid >> 32;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Parse HTTP method and path
    parse_http_request(args->buf, bytes_read, e->method, e->path);

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&active_read_args, &pid_tgid);
    return 0;
}

// ============================================================================
// Cleanup: close syscall to remove socket from tracking
// ============================================================================

SEC("tracepoint/syscalls/sys_enter_close")
int sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];

    // Remove socket info when fd is closed
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) | (__u64)fd;
    bpf_map_delete_elem(&socket_info_map, &sock_key);

    return 0;
}

char _license[] SEC("license") = "Dual BSD/GPL";
