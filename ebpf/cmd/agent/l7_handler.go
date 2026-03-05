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

	"k8s-ebpf-l4l7-metrics/internal/k8smapper" // K8s 메타데이터 매퍼
)

// HTTPEvent는 eBPF에서 전송된 L7 HTTP 요청 이벤트를 나타냄
// bpf/common/types.h의 struct http_event와 동일한 레이아웃
type HTTPEvent struct {
	Saddr      uint32    // 0-3: 소스 IP (클라이언트)
	Daddr      uint32    // 4-7: 목적지 IP (로컬)
	Sport      uint16    // 8-9: 소스 포트
	Dport      uint16    // 10-11: 목적지 포트
	Pid        uint32    // 12-15: 프로세스 ID
	Comm       [16]byte  // 16-31: 프로세스 이름
	PayloadLen uint32    // 32-35: 실제 읽은 데이터 길이
	Payload    [256]byte // 36-291: Raw HTTP 데이터
	Pad        uint32    // 292-295: 8바이트 정렬용 패딩
}

// HTTPEvent 구조체의 크기 (바이트 단위)
const httpEventSize = 296

// L7Handler는 L7 HTTP 요청 이벤트를 처리하는 핸들러
type L7Handler struct {
	reader        *ringbuf.Reader        // eBPF 링 버퍼 리더
	mapper        *k8smapper.Mapper      // K8s IP → 메타데이터 매퍼
	counter       *prometheus.CounterVec // Prometheus 카운터 메트릭
	healthFilter  *HealthCheckFilter     // 헬스체크 필터
	processFilter *L7ProcessFilter       // 프로세스 필터
}

// HealthCheckFilter는 헬스체크 요청을 필터링하는 구조체
type HealthCheckFilter struct {
	patterns   []string // 필터링할 경로 패턴 목록
	enabled    bool     // path 필터 활성화 여부
	uaPatterns []string // 필터링할 User-Agent 패턴 목록
	uaEnabled  bool     // UA 필터 활성화 여부
}

// L7ProcessFilter는 L7 이벤트를 프로세스 이름으로 필터링하는 구조체
type L7ProcessFilter struct {
	excludeComms map[string]struct{}
}

var defaultExcludeComms = []string{
	"node_exporter",
	"victoria-metric",
	"vmagent",
	"vmselect",
	"vminsert",
	"prometheus",
	"grafana",
	"alertmanager",
}

func NewL7ProcessFilter(customExcludeComms string) *L7ProcessFilter {
	f := &L7ProcessFilter{
		excludeComms: make(map[string]struct{}),
	}
	for _, comm := range defaultExcludeComms {
		f.excludeComms[strings.ToLower(comm)] = struct{}{}
	}
	for _, part := range strings.Split(customExcludeComms, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			f.excludeComms[strings.ToLower(part)] = struct{}{}
		}
	}
	return f
}

func (f *L7ProcessFilter) ShouldExclude(comm string) (bool, string) {
	commLower := strings.ToLower(comm)
	for prefix := range f.excludeComms {
		if strings.HasPrefix(commLower, prefix) {
			return true, prefix
		}
	}
	return false, ""
}

func (f *L7ProcessFilter) ExcludeCommsList() []string {
	list := make([]string, 0, len(f.excludeComms))
	for k := range f.excludeComms {
		list = append(list, k)
	}
	return list
}

var defaultHealthCheckPatterns = []string{
	"/healthz", "/readyz", "/livez", "/health", "/ready", "/live", "/ping", "/status", "/_health", "/metrics",
}

var defaultHealthCheckUAPatterns = []string{
	"elb-healthchecker", "kube-probe",
}

func NewHealthCheckFilter(enabled bool, customPatterns string, uaEnabled bool, customUAPatterns string) *HealthCheckFilter {
	patterns := make([]string, len(defaultHealthCheckPatterns))
	copy(patterns, defaultHealthCheckPatterns)
	if customPatterns != "" {
		for _, p := range strings.Split(customPatterns, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				patterns = append(patterns, strings.ToLower(p))
			}
		}
	}

	uaPatterns := make([]string, len(defaultHealthCheckUAPatterns))
	copy(uaPatterns, defaultHealthCheckUAPatterns)
	if customUAPatterns != "" {
		for _, p := range strings.Split(customUAPatterns, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				uaPatterns = append(uaPatterns, strings.ToLower(p))
			}
		}
	}

	return &HealthCheckFilter{
		patterns:   patterns,
		enabled:    enabled,
		uaPatterns: uaPatterns,
		uaEnabled:  uaEnabled,
	}
}

func (f *HealthCheckFilter) IsHealthCheck(path string) bool {
	if !f.enabled {
		return false
	}
	pathLower := strings.ToLower(path)
	for _, pattern := range f.patterns {
		if strings.HasPrefix(pathLower, pattern) {
			return true
		}
	}
	return false
}

func (f *HealthCheckFilter) IsHealthCheckUA(userAgent string) bool {
	if !f.uaEnabled || userAgent == "" {
		return false
	}
	uaLower := strings.ToLower(userAgent)
	for _, pattern := range f.uaPatterns {
		if strings.HasPrefix(uaLower, pattern) {
			return true
		}
	}
	return false
}

func (f *HealthCheckFilter) Patterns() []string   { return f.patterns }
func (f *HealthCheckFilter) UAPatterns() []string { return f.uaPatterns }

func NewL7Handler(reader *ringbuf.Reader, mapper *k8smapper.Mapper, counter *prometheus.CounterVec, healthFilter *HealthCheckFilter, processFilter *L7ProcessFilter) *L7Handler {
	return &L7Handler{
		reader:        reader,
		mapper:        mapper,
		counter:       counter,
		healthFilter:  healthFilter,
		processFilter: processFilter,
	}
}

func (h *L7Handler) Run(ctx context.Context) error {
	log.Println("[L7] Handler started; waiting for HTTP request events")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		record, err := h.reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return nil
			}
			log.Printf("[L7] ringbuf read error: %v", err)
			continue
		}
		h.processRecord(record)
	}
}

func (h *L7Handler) processRecord(record ringbuf.Record) {
	if len(record.RawSample) < httpEventSize {
		return
	}

	event := h.parseEvent(record.RawSample)
	method, path, userAgent := parseHTTPPayload(event.Payload[:], event.PayloadLen)
	comm := bytesToString(event.Comm[:])
	srcIP := uint32ToIP(event.Saddr)

	// 프로세스 필터링
	if excluded, _ := h.processFilter.ShouldExclude(comm); excluded {
		return
	}

	// 헬스체크 필터링 (Path)
	if h.healthFilter.IsHealthCheck(path) {
		log.Printf("[L7][FILTERED] src=%s path=%s (healthcheck excluded)", srcIP, path)
		return
	}

	// 헬스체크 필터링 (User-Agent)
	if h.healthFilter.IsHealthCheckUA(userAgent) {
		log.Printf("[L7][FILTERED] src=%s ua=%s (healthcheck ua excluded)", srcIP, userAgent)
		return
	}

	// K8s 메타데이터 조회
	var ns, svc, pod string = "unknown", "unknown", "unknown"
	if event.Daddr != 0 {
		dstIP := uint32ToIP(event.Daddr)
		if meta, ok := h.mapper.Lookup(dstIP.String()); ok {
			ns, svc, pod = meta.Namespace, meta.Service, meta.Pod
		}
	}

	h.counter.WithLabelValues(srcIP.String(), ns, svc, pod, method, path, comm).Inc()
	log.Printf("[L7][COUNTED] src=%s ns=%s svc=%s method=%s path=%s ua=%s", srcIP, ns, svc, method, path, userAgent)
}

func (h *L7Handler) parseEvent(raw []byte) HTTPEvent {
	var event HTTPEvent
	event.Saddr = binary.BigEndian.Uint32(raw[0:4])
	event.Daddr = binary.BigEndian.Uint32(raw[4:8])
	event.Sport = binary.LittleEndian.Uint16(raw[8:10])
	event.Dport = binary.LittleEndian.Uint16(raw[10:12])
	event.Pid = binary.LittleEndian.Uint32(raw[12:16])
	copy(event.Comm[:], raw[16:32])
	event.PayloadLen = binary.LittleEndian.Uint32(raw[32:36])
	copy(event.Payload[:], raw[36:292])
	return event
}

// parseHTTPPayload는 Raw Payload에서 HTTP 정보를 파싱함
func parseHTTPPayload(payload []byte, length uint32) (method, path, userAgent string) {
	if length > 256 {
		length = 256
	}
	data := payload[:length]

	// Request Line 파싱 (첫 줄)
	firstLineEnd := bytes.Index(data, []byte("\r\n"))
	if firstLineEnd < 0 {
		firstLineEnd = len(data)
	}
	requestLine := string(data[:firstLineEnd])
	parts := strings.SplitN(requestLine, " ", 3)
	if len(parts) >= 2 {
		method = parts[0]
		path = applyPathLimit(parts[1])
	}

	// User-Agent 헤더 검색 (Case-Insensitive)
	dataLower := bytes.ToLower(data)
	uaIdx := bytes.Index(dataLower, []byte("user-agent:"))
	if uaIdx >= 0 {
		valueStart := uaIdx + len("user-agent:")
		remaining := data[valueStart:]
		lineEnd := bytes.Index(remaining, []byte("\r\n"))
		if lineEnd < 0 {
			lineEnd = len(remaining)
		}
		userAgent = strings.TrimSpace(string(remaining[:lineEnd]))
		if len(userAgent) > 31 {
			userAgent = userAgent[:31]
		}
	}

	return
}

// applyPathLimit은 경로의 Depth를 2로 제한함 (eBPF 기존 로직 Go 구현)
func applyPathLimit(path string) string {
	if path == "" || path == "/" {
		return path
	}
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) > 2 {
		return "/" + parts[0] + "/" + parts[1] + "/*"
	}
	return path
}

func (h *L7Handler) Close() error { return h.reader.Close() }

func bytesToString(b []byte) string {
	if idx := bytes.IndexByte(b, 0); idx != -1 {
		return string(b[:idx])
	}
	return string(b)
}

func uint32ToIP(addr uint32) net.IP {
	ip := make(net.IP, net.IPv4len)
	binary.BigEndian.PutUint32(ip, addr)
	return ip
}
