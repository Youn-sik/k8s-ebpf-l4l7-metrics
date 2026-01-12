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
// 주의: bpf2go는 포인터 타입을 지원하지 않으므로 __u64로 주소 저장
struct accept_args_t {
    int sockfd;              // 리스닝 소켓 FD
    int _pad;                // 패딩 (8바이트 정렬)
    __u64 addr;              // struct sockaddr* 주소를 __u64로 저장
};

// read() 시스템콜 인자 저장용
// 주의: bpf2go는 포인터 타입을 지원하지 않으므로 __u64로 주소 저장
struct read_args_t {
    int fd;                  // 파일 디스크립터
    int _pad;                // 패딩 (8바이트 정렬)
    __u64 buf;               // char* 버퍼 주소를 __u64로 저장
};

// kretprobe에서 수집한 소켓 주소 임시 저장용
// pid_tgid를 키로 사용, sys_exit_accept4에서 병합
// inet_csk_accept의 struct sock에서 로컬/클라이언트 주소를 모두 수집
struct pending_sock_info_t {
    __u32 local_addr;        // Local IP (network byte order) - skc_rcv_saddr
    __u16 local_port;        // Local Port (host byte order) - skc_num
    __u16 _pad1;             // Padding
    __u32 client_addr;       // Client IP (network byte order) - skc_daddr
    __u16 client_port;       // Client Port (network byte order) - skc_dport
    __u16 _pad2;             // Padding
};

// 소켓 정보 (accept에서 추출한 클라이언트 및 로컬 정보)
struct socket_info_t {
    __u32 client_addr;    // Client IP (network byte order)
    __u16 client_port;    // Client Port (network byte order)
    __u16 _pad1;          // Padding for alignment
    __u32 local_addr;     // Local IP (network byte order) - 서버 주소
    __u16 local_port;     // Local Port (host byte order) - 리스닝 포트
    __u16 _pad2;          // Padding for alignment
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
