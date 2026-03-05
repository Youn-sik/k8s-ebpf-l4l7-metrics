// SPDX-License-Identifier: Dual BSD/GPL
// Common types for eBPF programs

#ifndef __BPF_COMMON_TYPES_H__
#define __BPF_COMMON_TYPES_H__

// ============================================================================
// L4 Outbound Types (tcp_connect)
// ============================================================================

struct l4_event {
    __u32 daddr;
    char comm[16];
};

// ============================================================================
// L7 Inbound Types (http_trace)
// ============================================================================

struct accept_args_t {
    int sockfd;
    int _pad;
    __u64 addr;
};

struct read_args_t {
    int fd;
    int _pad;
    __u64 buf;
};

struct pending_sock_info_t {
    __u32 local_addr;
    __u16 local_port;
    __u16 _pad1;
    __u32 client_addr;
    __u16 client_port;
    __u16 _pad2;
};

struct socket_info_t {
    __u32 client_addr;
    __u16 client_port;
    __u16 _pad1;
    __u32 local_addr;
    __u16 local_port;
    __u16 _pad2;
    __u64 accept_time;
};

// HTTP 이벤트 (유저스페이스 전달용)
// 총 크기: 4+4+2+2+4+16+4+256 + 4(pad) = 296 bytes (8바이트 정렬)
struct http_event {
    __u32 saddr;          // 0-3
    __u32 daddr;          // 4-7
    __u16 sport;          // 8-9
    __u16 dport;          // 10-11
    __u32 pid;            // 12-15
    char comm[16];        // 16-31
    __u32 payload_len;    // 32-35: 실제 읽은 데이터 길이
    char payload[256];    // 36-291: Raw HTTP 데이터
    __u32 _pad;           // 292-295: 8바이트 정렬용 패딩
};

// ============================================================================
// Constants
// ============================================================================

#ifndef AF_INET
#define AF_INET 2
#endif

#define HTTP_GET_MAGIC   0x20544547
#define HTTP_POST_MAGIC  0x54534F50
#define HTTP_PUT_MAGIC   0x20545550
#define HTTP_DELE_MAGIC  0x454C4544
#define HTTP_HEAD_MAGIC  0x44414548
#define HTTP_PATC_MAGIC  0x43544150
#define HTTP_OPTI_MAGIC  0x4954504F

#define MAX_ACTIVE_ACCEPT  16384
#define MAX_ACTIVE_READ    16384
#define MAX_SOCKET_INFO    65536
#define HTTP_RINGBUF_SIZE  (1024 * 1024)

#define MAX_PAYLOAD_LEN    256
#define MAX_PATH_DEPTH     2
#define MAX_PATH_LEN       64

#endif // __BPF_COMMON_TYPES_H__
