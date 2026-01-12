// SPDX-License-Identifier: Dual BSD/GPL
// L7 Inbound HTTP Request Tracer (L7 수신 HTTP 요청 추적기)
// Captures HTTP requests to Pods via sys_enter/exit_accept4 and sys_enter/exit_read.
// (sys_enter/exit_accept4 및 sys_enter/exit_read를 통해 Pod로 들어오는 HTTP 요청을 캡처)
// Used for detecting inbound HTTP traffic with method and path extraction.
// (HTTP 메서드와 경로 추출을 통해 수신 HTTP 트래픽 감지에 사용)

#include "vmlinux.h"              // 커널 데이터 구조체 정의 (BTF 기반)
#include <bpf/bpf_endian.h>       // 엔디안 변환 헬퍼 함수
#include <bpf/bpf_core_read.h>    // CO-RE(Compile Once - Run Everywhere) 읽기 함수
#include <bpf/bpf_helpers.h>      // BPF 헬퍼 함수 (맵 조작, 시간 등)
#include <bpf/bpf_tracing.h>      // 트레이싱 관련 매크로 및 함수

#include "../common/types.h"       // 공통 타입 정의 (이벤트 구조체, 상수 등)

// ============================================================================
// Maps (맵 정의)
// BPF 맵은 커널 공간과 유저 공간 간의 데이터 공유 및 상태 저장에 사용
// ============================================================================

// accept() 시스템 콜의 인자를 sys_enter와 sys_exit 사이에 저장하는 맵
// accept4()가 호출될 때 인자를 저장하고, 완료 시 결과와 함께 처리
struct {
    __uint(type, BPF_MAP_TYPE_HASH);           // 해시 맵 타입 (키-값 저장)
    __uint(max_entries, MAX_ACTIVE_ACCEPT);    // 최대 엔트리 수 (동시 accept 수)
    __type(key, __u64);                        // 키: pid_tgid (프로세스 ID + 스레드 그룹 ID)
    __type(value, struct accept_args_t);       // 값: accept 호출 인자 (소켓 fd, 주소 포인터)
} active_accept_args SEC(".maps");

// read() 시스템 콜의 인자를 sys_enter와 sys_exit 사이에 저장하는 맵
// read()가 호출될 때 버퍼 포인터를 저장하고, 완료 시 데이터 분석
struct {
    __uint(type, BPF_MAP_TYPE_HASH);           // 해시 맵 타입
    __uint(max_entries, MAX_ACTIVE_READ);      // 최대 엔트리 수 (동시 read 수)
    __type(key, __u64);                        // 키: pid_tgid
    __type(value, struct read_args_t);         // 값: read 호출 인자 (fd, 버퍼 포인터)
} active_read_args SEC(".maps");

// FD(파일 디스크립터)를 소켓 정보에 매핑하는 맵
// accept()에서 얻은 클라이언트 IP/Port 정보를 저장
// 키: (pid_tgid & 0xFFFFFFFF00000000) | fd (상위 32비트: PID, 하위 32비트: FD)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);           // 해시 맵 타입
    __uint(max_entries, MAX_SOCKET_INFO);      // 최대 소켓 정보 엔트리 수
    __type(key, __u64);                        // 키: PID와 FD의 조합
    __type(value, struct socket_info_t);       // 값: 소켓 정보 (클라이언트 주소, 포트, 타임스탬프)
} socket_info_map SEC(".maps");

// HTTP 이벤트를 유저스페이스로 전송하는 링 버퍼
// 링 버퍼는 perf 버퍼보다 효율적이며 이벤트 손실이 적음
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);        // 링 버퍼 맵 타입
    __uint(max_entries, HTTP_RINGBUF_SIZE);    // 버퍼 크기 (바이트 단위)
} http_events SEC(".maps");

// kretprobe에서 수집한 소켓 주소를 임시 저장하는 맵
// kretprobe/inet_csk_accept이 sys_exit_accept4보다 먼저 실행되므로
// 여기에 저장 후 sys_exit_accept4에서 socket_info_map에 병합
// 클라이언트 주소도 수집하여 accept4(fd, NULL, ...)인 경우에도 처리 가능
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_ACTIVE_ACCEPT);
    __type(key, __u64);                            // 키: pid_tgid
    __type(value, struct pending_sock_info_t);     // 값: 로컬 + 클라이언트 주소/포트
} pending_sock_info SEC(".maps");

// ============================================================================
// Helper Functions (헬퍼 함수)
// ============================================================================

// 버퍼가 HTTP 요청 메서드로 시작하는지 확인하는 함수
// HTTP 메서드의 처음 4바이트를 매직 넘버로 비교 (리틀 엔디안)
static __always_inline bool is_http_request(const char *buf)
{
    __u32 first4;
    // 유저 공간 메모리에서 처음 4바이트 읽기
    bpf_probe_read_user(&first4, sizeof(first4), buf);

    // 알려진 HTTP 메서드 매직 넘버와 비교 (리틀 엔디안 기준)
    if (first4 == HTTP_GET_MAGIC)  return true;  // "GET " (0x20544547)
    if (first4 == HTTP_POST_MAGIC) return true;  // "POST" (0x54534F50)
    if (first4 == HTTP_PUT_MAGIC)  return true;  // "PUT " (0x20545550)
    if (first4 == HTTP_DELE_MAGIC) return true;  // "DELE" (0x454C4544) - DELETE의 앞 4바이트
    if (first4 == HTTP_HEAD_MAGIC) return true;  // "HEAD" (0x44414548)
    if (first4 == HTTP_PATC_MAGIC) return true;  // "PATC" (0x43544150) - PATCH의 앞 4바이트
    if (first4 == HTTP_OPTI_MAGIC) return true;  // "OPTI" (0x4954504F) - OPTIONS의 앞 4바이트

    return false;
}

// HTTP 요청에서 메서드와 경로를 파싱하는 함수
// 경로는 MAX_PATH_DEPTH 레벨로 제한됨 (예: /api/users/* 형태로 잘림)
static __always_inline void parse_http_request(
    const char *buf,        // HTTP 요청 버퍼 포인터
    __s64 len,              // 버퍼 길이
    char *method_out,       // 메서드 출력 버퍼
    char *path_out)         // 경로 출력 버퍼
{
    char local_buf[128];    // 로컬 버퍼 (스택에 할당, BPF 스택 크기 제한 고려)
    int read_len = len > 127 ? 127 : len;  // 최대 127바이트만 읽기

    // 요청 라인을 로컬 버퍼로 읽기
    if (bpf_probe_read_user(local_buf, read_len, buf) < 0) {
        method_out[0] = '\0';  // 읽기 실패 시 빈 문자열
        path_out[0] = '\0';
        return;
    }
    local_buf[read_len] = '\0';  // 널 종료

    // 메서드 추출 (첫 번째 공백까지)
    int i = 0;
    #pragma unroll  // 컴파일러에게 루프 언롤링 지시 (BPF 검증기 통과용)
    for (; i < 7 && i < read_len; i++) {  // HTTP 메서드 최대 7자 (OPTIONS)
        if (local_buf[i] == ' ') break;   // 공백 발견 시 종료
        method_out[i] = local_buf[i];     // 메서드 문자 복사
    }
    method_out[i] = '\0';  // 널 종료

    // 공백을 건너뛰고 경로 시작점 찾기
    int path_start = i + 1;
    if (path_start >= read_len) {
        path_out[0] = '\0';  // 경로 없음
        return;
    }

    // 깊이 제한을 적용하여 경로 추출
    int depth = 0;      // 현재 경로 깊이 (슬래시 개수)
    int path_idx = 0;   // 출력 경로 인덱스

    // 경로 문자 복사 루프 (bounded loop - 커널 5.3+에서 자동 검증)
    for (int j = path_start; j < read_len && path_idx < (MAX_PATH_LEN - 2); j++) {
        char c = local_buf[j];

        // 경로 끝: 공백, 쿼리 스트링(?), 프래그먼트(#), 개행 문자
        if (c == ' ' || c == '?' || c == '#' || c == '\r' || c == '\n') {
            break;
        }

        // 슬래시에서 깊이 카운트 증가
        if (c == '/') {
            depth++;
            if (depth > MAX_PATH_DEPTH) {
                // 최대 깊이 초과 시 와일드카드로 잘라냄
                path_out[path_idx++] = '/';
                path_out[path_idx++] = '*';
                break;
            }
        }

        path_out[path_idx++] = c;  // 경로 문자 복사
    }
    path_out[path_idx] = '\0';  // 널 종료
}

// ============================================================================
// Tracepoints: accept4 syscall (accept4 시스템 콜 트레이스포인트)
// accept4()는 새로운 클라이언트 연결을 수락하는 시스템 콜
// ============================================================================

// accept4 시스템 콜 진입점 트레이스포인트
// 클라이언트 연결 수락 시작 시 호출됨
SEC("tracepoint/syscalls/sys_enter_accept4")
int sys_enter_accept4(struct trace_event_raw_sys_enter *ctx)
{
    // 현재 프로세스의 PID와 TGID(스레드 그룹 ID) 조합 가져오기
    // 상위 32비트: TGID (프로세스 ID), 하위 32비트: TID (스레드 ID)
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // accept4 인자 저장 구조체 초기화
    struct accept_args_t args = {};
    args.sockfd = (int)ctx->args[0];               // 첫 번째 인자: 리스닝 소켓 FD
    args.addr = (__u64)ctx->args[1];               // 두 번째 인자: 클라이언트 주소 저장 포인터 (주소값)

    // 맵에 인자 저장 (sys_exit에서 사용)
    bpf_map_update_elem(&active_accept_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// accept4 시스템 콜 종료점 트레이스포인트
// 클라이언트 연결 수락 완료 시 호출됨
// 클라이언트 주소 + kretprobe에서 수집한 로컬 주소를 병합
SEC("tracepoint/syscalls/sys_exit_accept4")
int sys_exit_accept4(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->ret;  // 반환값: 새로 생성된 소켓 FD (음수면 에러)

    // accept 실패 시 (fd < 0) 저장된 인자 삭제 후 종료
    if (fd < 0) {
        bpf_map_delete_elem(&active_accept_args, &pid_tgid);
        bpf_map_delete_elem(&pending_sock_info, &pid_tgid);
        return 0;
    }

    // 저장된 accept 인자 조회
    struct accept_args_t *args = bpf_map_lookup_elem(&active_accept_args, &pid_tgid);
    if (!args) {
        bpf_map_delete_elem(&pending_sock_info, &pid_tgid);
        return 0;  // 인자가 없으면 종료 (sys_enter를 놓친 경우)
    }

    // 소켓 정보 엔트리 생성
    struct socket_info_t info = {};
    info.accept_time = bpf_ktime_get_ns();  // 수락 시각 기록 (나노초)

    // kretprobe에서 수집한 소켓 정보 병합 (우선 사용)
    // kretprobe는 struct sock에서 직접 읽으므로 가장 신뢰할 수 있음
    struct pending_sock_info_t *pending = bpf_map_lookup_elem(&pending_sock_info, &pid_tgid);
    if (pending) {
        info.local_addr = pending->local_addr;    // 로컬 IP
        info.local_port = pending->local_port;    // 로컬 포트
        info.client_addr = pending->client_addr;  // 클라이언트 IP
        info.client_port = pending->client_port;  // 클라이언트 포트
        bpf_map_delete_elem(&pending_sock_info, &pid_tgid);
    }

    // kretprobe에서 클라이언트 정보를 못 얻은 경우, 유저 공간에서 읽기 시도
    // accept4(fd, addr, addrlen, flags)에서 addr이 NULL이 아닌 경우
    if (info.client_addr == 0 && args->addr) {
        struct sockaddr_in client_addr = {};
        if (bpf_probe_read_user(&client_addr, sizeof(client_addr), (void *)args->addr) == 0) {
            if (client_addr.sin_family == AF_INET) {
                info.client_addr = client_addr.sin_addr.s_addr;
                info.client_port = client_addr.sin_port;
            }
        }
    }

    // 키 생성: 상위 32비트 = PID, 하위 32비트 = FD
    // 이렇게 하면 프로세스별로 FD를 구분할 수 있음
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) | (__u64)fd;
    bpf_map_update_elem(&socket_info_map, &sock_key, &info, BPF_ANY);

    // 사용 완료된 accept 인자 삭제
    bpf_map_delete_elem(&active_accept_args, &pid_tgid);
    return 0;
}

// ============================================================================
// Kretprobe: inet_csk_accept (로컬 주소 수집)
// inet_csk_accept은 TCP accept의 핵심 커널 함수로, struct sock*를 반환
// 여기서 로컬(서버) 주소와 포트를 안정적으로 수집할 수 있음
// 실행 순서: sys_enter_accept4 → inet_csk_accept → kretprobe → sys_exit_accept4
// ============================================================================

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe_inet_csk_accept, struct sock *sk)
{
    // 반환값이 NULL이면 accept 실패
    if (!sk) {
        return 0;
    }

    __u64 pid_tgid = bpf_get_current_pid_tgid();

    // struct sock에서 주소 정보 읽기 (CO-RE 사용)
    // accept된 소켓에서:
    // - skc_rcv_saddr: 로컬(서버) IP - 서버가 0.0.0.0으로 바인딩하면 0일 수 있음
    // - skc_daddr: 원격(클라이언트) IP (network byte order)
    // - skc_num: 로컬 포트 (host byte order)
    // - skc_dport: 원격 포트 (network byte order)
    __u32 local_addr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    __u16 local_port = BPF_CORE_READ(sk, __sk_common.skc_num);
    __u32 client_addr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    __u16 client_port = BPF_CORE_READ(sk, __sk_common.skc_dport);

    // pending_sock_info 맵에 임시 저장
    // sys_exit_accept4에서 이 값을 가져와 socket_info_map에 병합
    struct pending_sock_info_t pending = {};
    pending.local_addr = local_addr;
    pending.local_port = local_port;
    pending.client_addr = client_addr;
    pending.client_port = client_port;

    bpf_map_update_elem(&pending_sock_info, &pid_tgid, &pending, BPF_ANY);

    return 0;
}

// ============================================================================
// Tracepoints: read syscall (read 시스템 콜 트레이스포인트)
// read()는 소켓에서 데이터를 읽는 시스템 콜
// HTTP 요청 데이터를 캡처하는 핵심 부분
// ============================================================================

// read 시스템 콜 진입점 트레이스포인트
// 소켓에서 데이터 읽기 시작 시 호출됨
SEC("tracepoint/syscalls/sys_enter_read")
int sys_enter_read(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];  // 첫 번째 인자: 파일 디스크립터

    // 이 FD가 추적 중인 소켓인지 확인
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) | (__u64)fd;
    if (!bpf_map_lookup_elem(&socket_info_map, &sock_key)) {
        return 0;  // 추적 대상 소켓이 아니면 무시
    }

    // read 인자 저장
    struct read_args_t args = {};
    args.fd = fd;
    args.buf = (__u64)ctx->args[1];   // 두 번째 인자: 데이터 저장 버퍼 포인터 (주소값)

    bpf_map_update_elem(&active_read_args, &pid_tgid, &args, BPF_ANY);
    return 0;
}

// read 시스템 콜 종료점 트레이스포인트
// 소켓에서 데이터 읽기 완료 시 호출됨
// HTTP 요청인지 확인하고 이벤트 생성
SEC("tracepoint/syscalls/sys_exit_read")
int sys_exit_read(struct trace_event_raw_sys_exit *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __s64 bytes_read = ctx->ret;  // 반환값: 읽은 바이트 수 (음수면 에러)

    // 읽기 실패 또는 데이터 없음
    if (bytes_read <= 0) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;
    }

    // 저장된 read 인자 조회
    struct read_args_t *args = bpf_map_lookup_elem(&active_read_args, &pid_tgid);
    if (!args) {
        return 0;
    }

    // HTTP 요청인지 확인 (메서드 매직 넘버 비교)
    // args->buf는 __u64로 저장된 포인터 주소이므로 char*로 캐스팅
    if (!is_http_request((const char *)args->buf)) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;  // HTTP 요청이 아니면 무시
    }

    // 링 버퍼에 이벤트 공간 예약
    struct http_event *e = bpf_ringbuf_reserve(&http_events, sizeof(*e), 0);
    if (!e) {
        bpf_map_delete_elem(&active_read_args, &pid_tgid);
        return 0;  // 버퍼 공간 부족 시 이벤트 드롭
    }

    // 소켓 정보로 이벤트 채우기
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) | (__u64)args->fd;
    struct socket_info_t *sock = bpf_map_lookup_elem(&socket_info_map, &sock_key);
    if (sock) {
        e->saddr = sock->client_addr;  // 클라이언트(소스) IP
        e->sport = sock->client_port;  // 클라이언트(소스) 포트
        e->daddr = sock->local_addr;   // 로컬(목적지) IP - kretprobe에서 수집
        // local_port는 host byte order이므로 network byte order로 변환
        e->dport = bpf_htons(sock->local_port);
    } else {
        e->saddr = 0;
        e->sport = 0;
        e->daddr = 0;
        e->dport = 0;
    }

    // 프로세스 정보 채우기
    e->pid = pid_tgid >> 32;  // 상위 32비트가 PID
    bpf_get_current_comm(&e->comm, sizeof(e->comm));  // 현재 프로세스 이름

    // HTTP 메서드와 경로 파싱
    // args->buf는 __u64로 저장된 포인터 주소이므로 char*로 캐스팅
    parse_http_request((const char *)args->buf, bytes_read, e->method, e->path);

    // 이벤트를 링 버퍼에 제출 (유저스페이스로 전송)
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&active_read_args, &pid_tgid);
    return 0;
}

// ============================================================================
// Cleanup: close syscall (정리: close 시스템 콜)
// 소켓이 닫힐 때 추적 맵에서 제거
// ============================================================================

// close 시스템 콜 진입점 트레이스포인트
// 파일 디스크립터 닫기 시 호출됨
SEC("tracepoint/syscalls/sys_enter_close")
int sys_enter_close(struct trace_event_raw_sys_enter *ctx)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    int fd = (int)ctx->args[0];  // 닫으려는 FD

    // FD가 닫힐 때 소켓 정보 맵에서 제거
    // 메모리 누수 방지 및 FD 재사용 시 오동작 방지
    __u64 sock_key = (pid_tgid & 0xFFFFFFFF00000000ULL) | (__u64)fd;
    bpf_map_delete_elem(&socket_info_map, &sock_key);

    return 0;
}

// BPF 프로그램 라이선스 선언 (GPL 호환 필수)
// 일부 BPF 헬퍼 함수는 GPL 라이선스에서만 사용 가능
char _license[] SEC("license") = "Dual BSD/GPL";
