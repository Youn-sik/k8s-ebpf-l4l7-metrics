package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"net"
	"strings"

	"github.com/cilium/ebpf/ringbuf"                 // eBPF 링 버퍼 읽기 라이브러리
	"github.com/prometheus/client_golang/prometheus" // Prometheus 메트릭 라이브러리

	"ebpf-k8s-internal-traffic-metrics/internal/k8smapper" // K8s 메타데이터 매퍼
)

// HTTPEvent는 eBPF에서 전송된 L7 HTTP 요청 이벤트를 나타냄
// bpf/common/types.h의 struct http_event와 동일한 레이아웃이어야 함
type HTTPEvent struct {
	Saddr  uint32   // 소스 IP (클라이언트, 네트워크 바이트 오더)
	Daddr  uint32   // 목적지 IP (로컬, 네트워크 바이트 오더)
	Sport  uint16   // 소스 포트 (클라이언트)
	Dport  uint16   // 목적지 포트 (로컬)
	Pid    uint32   // 프로세스 ID
	Comm   [16]byte // 프로세스 이름 (최대 16바이트)
	Method [8]byte  // HTTP 메서드 (GET, POST 등)
	Path   [64]byte // 요청 경로 (깊이 제한됨)
}

// HTTPEvent 구조체의 크기 (바이트 단위)
// sizeof(HTTPEvent): 4+4+2+2+4+16+8+64 = 104 바이트
const httpEventSize = 104

// L7Handler는 L7 HTTP 요청 이벤트를 처리하는 핸들러
type L7Handler struct {
	reader  *ringbuf.Reader        // eBPF 링 버퍼 리더
	mapper  *k8smapper.Mapper      // K8s IP → 메타데이터 매퍼
	counter *prometheus.CounterVec // Prometheus 카운터 메트릭
	filter  *HealthCheckFilter     // 헬스체크 필터
}

// HealthCheckFilter는 헬스체크 요청을 필터링하는 구조체
// 쿠버네티스의 liveness/readiness 프로브 등을 제외시킴
type HealthCheckFilter struct {
	patterns []string // 필터링할 경로 패턴 목록
	enabled  bool     // 필터 활성화 여부
}

// 기본 헬스체크 경로 패턴
// 쿠버네티스 및 일반적인 서비스에서 사용하는 헬스체크 엔드포인트
var defaultHealthCheckPatterns = []string{
	"/healthz", // 쿠버네티스 표준 헬스체크
	"/readyz",  // 쿠버네티스 readiness 프로브
	"/livez",   // 쿠버네티스 liveness 프로브
	"/health",  // 일반적인 헬스체크
	"/ready",   // readiness 체크
	"/live",    // liveness 체크
	"/ping",    // 핑 체크
	"/status",  // 상태 확인
	"/_health", // 언더스코어 프리픽스 헬스체크
}

// NewHealthCheckFilter는 새로운 헬스체크 필터를 생성함
// enabled: 필터 활성화 여부
// customPatterns: 콤마로 구분된 추가 패턴 (예: "/api/health,/v1/status")
func NewHealthCheckFilter(enabled bool, customPatterns string) *HealthCheckFilter {
	// 기본 패턴을 복사하여 시작
	patterns := make([]string, len(defaultHealthCheckPatterns))
	copy(patterns, defaultHealthCheckPatterns)

	// 커스텀 패턴 추가
	if customPatterns != "" {
		for _, p := range strings.Split(customPatterns, ",") {
			p = strings.TrimSpace(p) // 공백 제거
			if p != "" {
				patterns = append(patterns, strings.ToLower(p)) // 소문자로 정규화
			}
		}
	}

	return &HealthCheckFilter{
		patterns: patterns,
		enabled:  enabled,
	}
}

// IsHealthCheck는 주어진 경로가 헬스체크 엔드포인트인지 확인함
// 프리픽스 매칭 방식으로 검사 (예: /healthz/live도 매칭됨)
func (f *HealthCheckFilter) IsHealthCheck(path string) bool {
	// 필터가 비활성화되어 있으면 항상 false
	if !f.enabled {
		return false
	}

	// 대소문자 구분 없이 비교하기 위해 소문자로 변환
	pathLower := strings.ToLower(path)
	for _, pattern := range f.patterns {
		// 프리픽스 매칭: /healthz로 시작하는 모든 경로 매칭
		if strings.HasPrefix(pathLower, pattern) {
			return true
		}
	}
	return false
}

// Patterns는 설정된 헬스체크 패턴 목록을 반환함
// 로깅 및 디버깅 용도
func (f *HealthCheckFilter) Patterns() []string {
	return f.patterns
}

// NewL7Handler는 새로운 L7 HTTP 이벤트 핸들러를 생성함
// reader: eBPF 링 버퍼에서 이벤트를 읽는 리더
// mapper: IP 주소를 K8s 메타데이터로 변환하는 매퍼
// counter: Prometheus 메트릭 카운터
// filter: 헬스체크 필터
func NewL7Handler(reader *ringbuf.Reader, mapper *k8smapper.Mapper, counter *prometheus.CounterVec, filter *HealthCheckFilter) *L7Handler {
	return &L7Handler{
		reader:  reader,
		mapper:  mapper,
		counter: counter,
		filter:  filter,
	}
}

// Run은 L7 이벤트 처리 루프를 시작함
// 컨텍스트가 취소될 때까지 무한 루프로 이벤트를 처리
func (h *L7Handler) Run(ctx context.Context) error {
	log.Println("[L7] Handler started; waiting for HTTP request events")

	// 필터 설정 로깅
	if h.filter.enabled {
		log.Printf("[L7] Health check filter enabled, patterns=%v", h.filter.Patterns())
	} else {
		log.Println("[L7] Health check filter disabled")
	}

	// 메인 이벤트 처리 루프
	for {
		// 컨텍스트 취소 확인 (graceful shutdown)
		select {
		case <-ctx.Done():
			log.Println("[L7] Handler stopped")
			return ctx.Err()
		default:
			// 계속 진행
		}

		// 링 버퍼에서 다음 레코드 읽기 (블로킹 호출)
		record, err := h.reader.Read()
		if err != nil {
			// 링 버퍼가 닫힌 경우 (정상 종료)
			if errors.Is(err, ringbuf.ErrClosed) {
				log.Println("[L7] ringbuf reader closed; exiting")
				return nil
			}
			// 읽기 오류 (로깅 후 계속 시도)
			log.Printf("[L7] ringbuf read error: %v", err)
			continue
		}

		// 레코드 처리
		h.processRecord(record)
	}
}

// processRecord는 단일 HTTP 이벤트 레코드를 처리함
func (h *L7Handler) processRecord(record ringbuf.Record) {
	// 레코드 크기 검증
	if len(record.RawSample) < httpEventSize {
		log.Printf("[L7] decode error: short sample (%d bytes, want %d)", len(record.RawSample), httpEventSize)
		return
	}

	// 바이트 배열을 HTTPEvent 구조체로 파싱
	event := h.parseEvent(record.RawSample)

	// 바이트 배열에서 문자열 추출 (널 종료 처리)
	method := bytesToString(event.Method[:]) // HTTP 메서드 (예: GET, POST)
	path := bytesToString(event.Path[:])     // 요청 경로 (예: /api/users)
	comm := bytesToString(event.Comm[:])     // 프로세스 이름 (예: nginx)

	// IP 주소 변환 (uint32 → net.IP)
	srcIP := uint32ToIP(event.Saddr) // 클라이언트 IP
	// dstIP := uint32ToIP(event.Daddr) // 현재 사용 안함

	// 헬스체크 필터 적용 (메트릭에서 완전히 제외)
	if h.filter.IsHealthCheck(path) {
		log.Printf("[L7][FILTERED] src=%s method=%s path=%s comm=%s (excluded)", srcIP, method, path, comm)
		return // 헬스체크는 메트릭에 포함하지 않음
	}

	// K8s 메타데이터 조회
	// 기본값 설정 (매핑 실패 시 "unknown" 사용)
	var ns, svc, pod string = "unknown", "unknown", "unknown"

	// 목적지 IP로 K8s 메타데이터 조회 시도
	// 현재 구현에서 daddr는 0일 수 있음 (sys_enter_read에서 로컬 주소 미수집)
	if event.Daddr != 0 {
		dstIP := uint32ToIP(event.Daddr)
		if meta, ok := h.mapper.Lookup(dstIP.String()); ok {
			ns = meta.Namespace // 네임스페이스 (예: default)
			svc = meta.Service  // 서비스 이름 (예: my-service)
			pod = meta.Pod      // Pod 이름 (예: my-service-abc123)
		}
	}

	// Prometheus 메트릭 업데이트
	// 라벨: source_ip, destination_namespace, destination_service, destination_pod, method, path, process_comm
	h.counter.WithLabelValues(
		srcIP.String(), // 클라이언트 IP
		ns,             // 목적지 네임스페이스
		svc,            // 목적지 서비스
		pod,            // 목적지 Pod
		method,         // HTTP 메서드
		path,           // 요청 경로 (eBPF에서 깊이 제한됨)
		comm,           // 요청을 처리한 프로세스
	).Inc() // 카운터 1 증가

	log.Printf("[L7][COUNTED] src=%s ns=%s svc=%s pod=%s method=%s path=%s comm=%s",
		srcIP, ns, svc, pod, method, path, comm)
}

// parseEvent는 원시 바이트를 HTTPEvent 구조체로 파싱함
// 바이트 오프셋을 기반으로 각 필드를 추출
func (h *L7Handler) parseEvent(raw []byte) HTTPEvent {
	var event HTTPEvent

	// 리틀 엔디안으로 필드 파싱 (x86 아키텍처 기준)
	event.Saddr = binary.LittleEndian.Uint32(raw[0:4])   // 오프셋 0-3: 소스 IP
	event.Daddr = binary.LittleEndian.Uint32(raw[4:8])   // 오프셋 4-7: 목적지 IP
	event.Sport = binary.LittleEndian.Uint16(raw[8:10])  // 오프셋 8-9: 소스 포트
	event.Dport = binary.LittleEndian.Uint16(raw[10:12]) // 오프셋 10-11: 목적지 포트
	event.Pid = binary.LittleEndian.Uint32(raw[12:16])   // 오프셋 12-15: PID
	copy(event.Comm[:], raw[16:32])                      // 오프셋 16-31: 프로세스 이름 (16바이트)
	copy(event.Method[:], raw[32:40])                    // 오프셋 32-39: HTTP 메서드 (8바이트)
	copy(event.Path[:], raw[40:104])                     // 오프셋 40-103: 요청 경로 (64바이트)

	return event
}

// Close는 링 버퍼 리더를 닫음
// 핸들러 종료 시 호출하여 리소스 해제
func (h *L7Handler) Close() error {
	return h.reader.Close()
}

// bytesToString은 널 종료된 바이트 배열을 문자열로 변환함
// C 스타일 문자열 처리 (널 문자 이후는 무시)
func bytesToString(b []byte) string {
	// 널 문자 위치 찾기
	if idx := bytes.IndexByte(b, 0); idx != -1 {
		return string(b[:idx]) // 널 문자 전까지만 반환
	}
	return string(b) // 널 문자 없으면 전체 반환
}

// uint32ToIP는 uint32 (네트워크 바이트 오더)를 net.IP로 변환함
// eBPF는 네트워크 바이트 오더(빅 엔디안)로 IP 주소를 저장
func uint32ToIP(addr uint32) net.IP {
	ip := make(net.IP, net.IPv4len) // 4바이트 IPv4 주소
	// 빅 엔디안으로 변환 (네트워크 바이트 오더 유지)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}
