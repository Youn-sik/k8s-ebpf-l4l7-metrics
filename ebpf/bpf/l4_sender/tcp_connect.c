// SPDX-License-Identifier: Dual BSD/GPL
// L4 Outbound TCP Connect Tracer (L4 송신 TCP 연결 추적기)
// Captures destination IPv4 address on tcp_v4_connect and publishes via ring buffer.
// (tcp_v4_connect에서 목적지 IPv4 주소를 캡처하여 링 버퍼로 전송)
// Used for detecting outbound traffic from Pods (scale-from-zero trigger).
// (Pod에서 나가는 아웃바운드 트래픽 감지에 사용 - scale-from-zero 트리거)

#include "vmlinux.h"              // 커널 데이터 구조체 정의 (BTF 기반)
#include <bpf/bpf_endian.h>       // 엔디안 변환 헬퍼 함수 (네트워크 바이트 오더 처리)
#include <bpf/bpf_core_read.h>    // CO-RE(Compile Once - Run Everywhere) 읽기 함수
#include <bpf/bpf_helpers.h>      // BPF 헬퍼 함수 (맵 조작, 시간 등)
#include <bpf/bpf_tracing.h>      // kprobe/kretprobe 트레이싱 매크로

#include "../common/types.h"       // 공통 타입 정의 (이벤트 구조체, 상수 등)

// Legacy sockaddr 구조체 - 유저 공간 포인터에서 읽기 위한 용도
// 커널의 sockaddr_in과 동일한 레이아웃
struct ipv4_sockaddr {
    __u16 sin_family;     // 주소 패밀리 (AF_INET = 2)
    __u16 sin_port;       // 포트 번호 (네트워크 바이트 오더)
    __u32 sin_addr;       // IPv4 주소 (네트워크 바이트 오더)
};

// L4 송신 이벤트를 유저스페이스로 전송하는 링 버퍼
// 링 버퍼는 perf 버퍼보다 효율적이며 락 없는 구현으로 성능이 우수
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);  // 링 버퍼 맵 타입
    __uint(max_entries, 256 * 1024);     // 256KB 버퍼 크기
} l4_events SEC(".maps");

// tcp_v4_connect 커널 함수에 연결되는 kprobe
// TCP IPv4 연결이 시작될 때 호출됨 (connect() 시스템 콜 시)
//
// 파라미터:
// - sk: 소켓 구조체 포인터 (연결 정보 포함)
// - uaddr: 유저가 전달한 목적지 주소 구조체 포인터
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect_enter, struct sock *sk, struct sockaddr *uaddr)
{
    __u32 daddr = 0;                    // 목적지 IP 주소
    struct l4_event *e;                 // 링 버퍼 이벤트 포인터
    struct ipv4_sockaddr sa = {};       // 소켓 주소 임시 저장 구조체

    // 1) 먼저 소켓 구조체에서 목적지 주소 읽기 시도
    // 이미 소켓에 설정된 경우가 있음 (재연결 등)
    if (sk) {
        // BPF_CORE_READ: CO-RE 방식으로 커널 구조체 필드 읽기
        // __sk_common.skc_daddr: 소켓의 목적지 IPv4 주소 필드
        daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    }

    // 2) 소켓에서 못 읽었으면 호출자가 전달한 sockaddr에서 읽기 시도
    // connect() 호출 시 유저가 직접 전달하는 주소
    if (!daddr && uaddr) {
        // 커널 메모리에서 sockaddr 구조체 읽기
        bpf_probe_read_kernel(&sa, sizeof(sa), uaddr);
        // IPv4 주소인 경우만 처리 (AF_INET = 2)
        if (sa.sin_family == AF_INET) {
            daddr = sa.sin_addr;  // 네트워크 바이트 오더 그대로 사용
        }
    }

    // 목적지 주소를 얻지 못했으면 이벤트 생성하지 않음
    if (!daddr)
        return 0;

    // 링 버퍼에 이벤트 공간 예약
    // sizeof(*e) 크기의 공간을 예약하고 포인터 반환
    e = bpf_ringbuf_reserve(&l4_events, sizeof(*e), 0);
    if (!e)
        return 0;  // 버퍼 공간 부족 시 이벤트 드롭

    // 이벤트 데이터 채우기
    e->daddr = daddr;  // 목적지 IP 주소 (네트워크 바이트 오더)
    // 현재 프로세스 이름 가져오기 (최대 16바이트)
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // 이벤트를 링 버퍼에 제출 (유저스페이스로 전송)
    // 플래그 0: 기본 동작 (즉시 전송)
    bpf_ringbuf_submit(e, 0);
    return 0;
}

// BPF 프로그램 라이선스 선언 (GPL 호환 필수)
// GPL 라이선스가 필요한 이유:
// 1. 일부 BPF 헬퍼 함수는 GPL 라이선스에서만 사용 가능
// 2. bpf_probe_read_kernel 등의 함수 사용에 필요
char _license[] SEC("license") = "Dual BSD/GPL";
