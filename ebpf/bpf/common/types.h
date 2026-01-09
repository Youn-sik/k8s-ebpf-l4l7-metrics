// SPDX-License-Identifier: Dual BSD/GPL
// Common types for eBPF programs
// L4 Outbound (tcp_connect) and L7 Inbound (http_trace) shared definitions

#ifndef __BPF_COMMON_TYPES_H__
#define __BPF_COMMON_TYPES_H__

// ============================================================================
// L4 Outbound Types (tcp_connect)
// ============================================================================

// L4 송신 이벤트 (tcp_v4_connect에서 수집)
struct l4_event {
    __u32 daddr;      // Destination IPv4 (network byte order)
    char comm[16];    // Process name
};

// ============================================================================
// L7 Inbound Types (http_trace)
// ============================================================================

// accept() 시스템콜 인자 저장용
struct accept_args_t {
    int sockfd;
    struct sockaddr *addr;
};

// read() 시스템콜 인자 저장용
struct read_args_t {
    int fd;
    char *buf;
};

// 소켓 정보 (accept에서 추출한 클라이언트 정보)
struct socket_info_t {
    __u32 client_addr;    // Client IP (network byte order)
    __u16 client_port;    // Client Port (network byte order)
    __u16 _pad;           // Padding for alignment
    __u64 accept_time;    // Connection accept timestamp (ns)
};

// HTTP 이벤트 (User Space로 전달)
struct http_event {
    __u32 saddr;          // Source IP - Client (network byte order)
    __u32 daddr;          // Destination IP - Local (network byte order)
    __u16 sport;          // Source Port - Client
    __u16 dport;          // Destination Port - Local (listening port)
    __u32 pid;            // Process ID
    char comm[16];        // Process name
    char method[8];       // HTTP Method (GET, POST, PUT, DELETE, HEAD, PATCH, OPTIONS)
    char path[64];        // Request Path (Depth 2 limited, e.g., /api/users/*)
};

// ============================================================================
// Constants
// ============================================================================

#ifndef AF_INET
#define AF_INET 2
#endif

// HTTP method detection magic numbers (little-endian)
#define HTTP_GET_MAGIC   0x20544547  // "GET "
#define HTTP_POST_MAGIC  0x54534F50  // "POST"
#define HTTP_PUT_MAGIC   0x20545550  // "PUT "
#define HTTP_DELE_MAGIC  0x454C4544  // "DELE" (DELETE)
#define HTTP_HEAD_MAGIC  0x44414548  // "HEAD"
#define HTTP_PATC_MAGIC  0x43544150  // "PATC" (PATCH)
#define HTTP_OPTI_MAGIC  0x4954504F  // "OPTI" (OPTIONS)

// Map size constants
#define MAX_ACTIVE_ACCEPT  16384   // Concurrent accept() calls
#define MAX_ACTIVE_READ    16384   // Concurrent read() calls
#define MAX_SOCKET_INFO    65536   // Active socket connections per node
#define HTTP_RINGBUF_SIZE  (1024 * 1024)  // 1MB for HTTP events

// Path parsing constants
#define MAX_PATH_DEPTH     2       // Maximum path depth before truncation
#define MAX_PATH_LEN       64      // Maximum path length in bytes
#define MAX_METHOD_LEN     8       // Maximum HTTP method length

#endif // __BPF_COMMON_TYPES_H__
