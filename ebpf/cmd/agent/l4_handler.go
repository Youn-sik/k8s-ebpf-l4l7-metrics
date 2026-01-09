package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strings"

	"github.com/cilium/ebpf/ringbuf"              // eBPF 링 버퍼 읽기 라이브러리
	"github.com/prometheus/client_golang/prometheus" // Prometheus 메트릭 라이브러리

	"ebpf-k8s-internal-traffic-metrics/internal/k8smapper" // K8s IP → 메타데이터 매퍼
)

// L4Event는 eBPF에서 전송된 L4 아웃바운드 TCP 연결 이벤트를 나타냄
// bpf/common/types.h의 struct l4_event와 동일한 레이아웃이어야 함
type L4Event struct {
	Daddr uint32   // 목적지 IPv4 주소 (네트워크 바이트 오더)
	Comm  [16]byte // 프로세스 이름 (최대 16바이트, 널 종료)
}

// L4Event 구조체의 크기 (바이트 단위)
// sizeof(L4Event): 4 (daddr) + 16 (comm) = 20 바이트
const l4EventSize = 20

// L4Handler는 L4 아웃바운드 TCP 연결 이벤트를 처리하는 핸들러
type L4Handler struct {
	reader  *ringbuf.Reader          // eBPF 링 버퍼 리더
	mapper  *k8smapper.Mapper        // K8s IP → 메타데이터 매퍼
	counter *prometheus.CounterVec   // Prometheus 카운터 메트릭
	filter  *L4Filter                // L4 이벤트 필터 (프로세스 제외용)
}

// L4Filter는 L4 이벤트를 필터링하는 구조체
// 특정 프로세스(kubelet 등)로부터의 이벤트를 제외시킴
type L4Filter struct {
	excludeComms map[string]struct{} // 제외할 프로세스 이름 (프리픽스 매칭)
}

// NewL4Filter는 새로운 L4 필터를 생성함
// customExcludeComms: 콤마로 구분된 추가 제외 프로세스 목록
func NewL4Filter(customExcludeComms string) *L4Filter {
	f := &L4Filter{
		excludeComms: make(map[string]struct{}),
	}

	// 기본 제외 목록
	// kubelet: 쿠버네티스 노드 에이전트로, 빈번한 헬스체크/모니터링 연결 발생
	f.excludeComms["kubelet"] = struct{}{}

	// 커스텀 제외 목록 추가
	for _, part := range strings.Split(customExcludeComms, ",") {
		part = strings.TrimSpace(part) // 앞뒤 공백 제거
		if part != "" {
			f.excludeComms[strings.ToLower(part)] = struct{}{} // 소문자로 정규화
		}
	}

	return f
}

// ShouldExclude는 주어진 프로세스가 제외 대상인지 확인함
// 프리픽스 매칭 방식 사용 (예: "kubelet"은 "kubelet-xyz"도 매칭)
// 반환값: (제외 여부, 매칭된 프리픽스)
func (f *L4Filter) ShouldExclude(comm string) (bool, string) {
	commLower := strings.ToLower(comm) // 대소문자 무시
	for prefix := range f.excludeComms {
		if strings.HasPrefix(commLower, prefix) {
			return true, prefix // 제외 대상
		}
	}
	return false, "" // 제외 대상 아님
}

// ExcludeCommsList는 제외 프로세스 프리픽스 목록을 반환함
// 로깅 및 디버깅 용도
func (f *L4Filter) ExcludeCommsList() []string {
	list := make([]string, 0, len(f.excludeComms))
	for k := range f.excludeComms {
		list = append(list, k)
	}
	return list
}

// NewL4Handler는 새로운 L4 이벤트 핸들러를 생성함
// reader: eBPF 링 버퍼에서 이벤트를 읽는 리더
// mapper: IP 주소를 K8s 메타데이터로 변환하는 매퍼
// counter: Prometheus 메트릭 카운터
// filter: 프로세스 필터
func NewL4Handler(reader *ringbuf.Reader, mapper *k8smapper.Mapper, counter *prometheus.CounterVec, filter *L4Filter) *L4Handler {
	return &L4Handler{
		reader:  reader,
		mapper:  mapper,
		counter: counter,
		filter:  filter,
	}
}

// Run은 L4 이벤트 처리 루프를 시작함
// 컨텍스트가 취소될 때까지 무한 루프로 이벤트를 처리
func (h *L4Handler) Run(ctx context.Context) error {
	log.Println("[L4] Handler started; waiting for TCP connect events")

	// 필터 설정 로깅
	log.Printf("[L4] excludeComms=%v (count=%d)", h.filter.ExcludeCommsList(), len(h.filter.excludeComms))

	// 메인 이벤트 처리 루프
	for {
		// 컨텍스트 취소 확인 (graceful shutdown)
		select {
		case <-ctx.Done():
			log.Println("[L4] Handler stopped")
			return ctx.Err()
		default:
			// 계속 진행
		}

		// 링 버퍼에서 다음 레코드 읽기 (블로킹 호출)
		record, err := h.reader.Read()
		if err != nil {
			// 링 버퍼가 닫힌 경우 (정상 종료)
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[L4] ringbuf reader closed; exiting")
				return nil
			}
			// 읽기 오류 (로깅 후 계속 시도)
			log.Printf("[L4] ringbuf read error: %v", err)
			continue
		}

		// 레코드 처리
		h.processRecord(record)
	}
}

// processRecord는 단일 L4 이벤트 레코드를 처리함
func (h *L4Handler) processRecord(record ringbuf.Record) {
	// 레코드 크기 검증
	if len(record.RawSample) < l4EventSize {
		log.Printf("[L4] decode error: short sample (%d bytes, want %d)", len(record.RawSample), l4EventSize)
		return
	}

	raw := record.RawSample

	// 목적지 주소 파싱 (네트워크 바이트 오더 = 빅 엔디안)
	// eBPF에서 네트워크 바이트 오더로 저장됨
	addr := binary.BigEndian.Uint32(raw[:4])

	// 프로세스 이름 파싱 (널 종료 문자열)
	commRaw := raw[4:l4EventSize] // 오프셋 4-19 (16바이트)
	comm := string(commRaw)
	// 널 문자 위치 찾아서 자르기 (C 스타일 문자열 처리)
	if idx := bytes.IndexByte(commRaw, 0); idx != -1 {
		comm = string(commRaw[:idx])
	}

	// uint32를 net.IP로 변환
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, addr) // 빅 엔디안 유지

	// 프로세스 필터 적용
	if excluded, matchedPrefix := h.filter.ShouldExclude(comm); excluded {
		log.Printf("[L4][FILTERED] dest=%s comm=%s matched=%s", ip.String(), comm, matchedPrefix)
		return // 필터링된 프로세스는 메트릭에서 제외
	}

	// K8s 메타데이터 조회
	// 목적지 IP를 K8s Pod/Service로 매핑
	meta, ok := h.mapper.Lookup(ip.String())
	if !ok {
		// 매핑 실패: K8s 내부 IP가 아니거나 아직 캐시에 없음
		log.Printf("[L4][UNMAPPED] dest=%s comm=%s", ip.String(), comm)
		return // 매핑되지 않은 IP는 메트릭에서 제외
	}

	// 메타데이터 추출 (기본값: "unknown")
	ns := meta.Namespace   // 네임스페이스 (예: default)
	svc := meta.Service    // 서비스 이름 (예: my-service)
	pod := meta.Pod        // Pod 이름 (예: my-service-abc123)
	if ns == "" {
		ns = "unknown"
	}
	if svc == "" {
		svc = "unknown"
	}
	if pod == "" {
		pod = "unknown"
	}

	// Prometheus 메트릭 업데이트
	// 라벨: destination_namespace, destination_service, destination_pod, process_comm
	h.counter.WithLabelValues(ns, svc, pod, comm).Inc() // 카운터 1 증가
	log.Printf("[L4][COUNTED] dest=%s ns=%s svc=%s pod=%s comm=%s", ip.String(), ns, svc, pod, comm)
}

// Close는 링 버퍼 리더를 닫음
// 핸들러 종료 시 호출하여 리소스 해제
func (h *L4Handler) Close() error {
	return h.reader.Close()
}
