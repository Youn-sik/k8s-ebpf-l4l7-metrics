## k8s-ebpf-l4l7-metrics: eBPF 기반 L4/L7 트래픽 감지 에이전트

**목표:** 파드가 0개일 때도 내부 TCP/HTTP 트래픽을 감지하여 KEDA 스케일 신호를 제공하는 초경량 eBPF 에이전트.

---

## 기술 개요

### 핵심 접근 방식

본 프로젝트는 **Linux 커널 레벨에서 네트워크 이벤트를 관찰**하는 eBPF(extended Berkeley Packet Filter) 기술을 활용합니다. 애플리케이션 코드 변경 없이 모든 TCP 연결과 HTTP 요청을 투명하게 캡처합니다.

### 기존 접근법과의 비교

| 접근 방식 | 단점 | 본 프로젝트 |
|-----------|------|-------------|
| **사이드카 프록시** (Istio, Linkerd) | 리소스 오버헤드, 복잡성, 레이턴시 증가 | 커널 레벨 후킹으로 오버헤드 최소화 |
| **SDK 방식** | 코드 변경 필수, 언어별 구현 필요 | 무침투적 - 앱 수정 불필요 |
| **네트워크 장비** | 비용, 클라우드 환경 제약 | 소프트웨어 기반, 클라우드 네이티브 |

### eBPF의 장점

- **무침투적**: 기존 인프라와 애플리케이션 변경 없이 모니터링 가능
- **저오버헤드**: 커널 네이티브 실행으로 성능 영향 최소화
- **실시간**: 이벤트 발생 즉시 감지 가능 (밀리초 단위)
- **범용성**: 모든 언어, 프레임워크, 프로토콜에 적용 가능
- **안전성**: 커널 검증기가 eBPF 코드 안정성 보장

---

## 아키텍처

```
┌─────────────────────────────────────────────────────────────────┐
│                         Kubernetes Cluster                       │
├─────────────────────────────────────────────────────────────────┤
│  ┌─────────────┐    ┌─────────────┐    ┌─────────────┐         │
│  │   Pod A     │    │   Pod B     │    │   Pod C     │         │
│  │  (scaled 0) │    │  (client)   │    │  (server)   │         │
│  └─────────────┘    └──────┬──────┘    └──────▲──────┘         │
│                            │                   │                 │
│                      tcp_connect()        accept()               │
│                            │                   │                 │
├────────────────────────────┼───────────────────┼─────────────────┤
│  Linux Kernel              │                   │                 │
│  ┌─────────────────────────┴───────────────────┴───────────────┐│
│  │                      eBPF Programs                          ││
│  │  ┌──────────────────┐      ┌──────────────────────────────┐ ││
│  │  │ kprobe:          │      │ kretprobe:                   │ ││
│  │  │ tcp_v4_connect   │      │ inet_csk_accept              │ ││
│  │  │ (L4 Outbound)    │      │ (L7 Inbound Socket)          │ ││
│  │  └────────┬─────────┘      └──────────────┬───────────────┘ ││
│  │           │                               │                  ││
│  │           └───────────┬───────────────────┘                  ││
│  │                       ▼                                      ││
│  │              ┌─────────────────┐                             ││
│  │              │   Ring Buffer   │                             ││
│  │              └────────┬────────┘                             ││
│  └───────────────────────┼──────────────────────────────────────┘│
│                          ▼                                       │
│  ┌───────────────────────────────────────────────────────────┐  │
│  │                  Userspace Agent                          │  │
│  │  ┌────────────┐  ┌─────────────┐  ┌────────────────────┐  │  │
│  │  │ K8s Mapper │  │Event Handler│  │ Prometheus Metrics │  │  │
│  │  │ (IP→Svc)   │  │ (L4/L7)     │  │     Exporter       │  │  │
│  │  └────────────┘  └─────────────┘  └────────────────────┘  │  │
│  └───────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
                              │
                              ▼
              ┌───────────────────────────────┐
              │     Prometheus / KEDA         │
              │  (메트릭 수집 & 오토스케일링)   │
              └───────────────────────────────┘
```

---

## 감지 계층

### L4 계층: TCP 연결 감지 (송신)

| 항목 | 내용 |
|------|------|
| **Hook Point** | `kprobe/tcp_v4_connect` |
| **감지 대상** | TCP 송신 연결 시도 |
| **수집 정보** | 목적지 IP/Port, 프로세스명(comm) |
| **메트릭** | `internal_tcp_attempts_total` |

**동작 흐름:**
1. K8s API 감시 → Services/EndpointSlices로 ClusterIP/PodIP 매핑 테이블 구축
2. `tcp_v4_connect` kprobe에서 목적지 IP와 프로세스명 캡처
3. IP를 K8s 메타데이터(namespace, service, pod)로 변환
4. Prometheus 카운터 증가

### L7 계층: HTTP 요청 감지 (수신)

| 항목 | 내용 |
|------|------|
| **Hook Point** | `kretprobe/inet_csk_accept` + `tracepoint/syscalls/sys_*_read` |
| **감지 대상** | HTTP 수신 요청 |
| **수집 정보** | 소스/목적지 IP, HTTP 메서드, 경로, 프로세스명 |
| **메트릭** | `internal_http_requests_total` |

**동작 흐름:**
1. `inet_csk_accept` kretprobe에서 수신 소켓의 클라이언트/서버 IP 캡처
2. `sys_enter/exit_read`에서 HTTP 요청 메서드/경로 파싱
3. 목적지 IP를 K8s 메타데이터로 변환 (수신 Pod의 namespace, service, pod)
4. 헬스체크 경로(/healthz, /metrics 등) 자동 필터링
5. Prometheus 카운터 증가

---

## 주요 기능

| 계층 | 감지 대상 | Hook Point | 메트릭 |
|------|----------|------------|--------|
| **L4** | TCP 송신 연결 시도 | `kprobe/tcp_v4_connect` | `internal_tcp_attempts_total` |
| **L7** | HTTP 수신 요청 | `kretprobe/inet_csk_accept` + `tracepoint` | `internal_http_requests_total` |

---

## 왜 0 파드에서도 감지 가능한가?

### Zero Scaling 지원

본 프로젝트의 핵심 비즈니스 가치는 **파드가 0개로 축소된 서비스에 대한 트래픽도 감지**할 수 있다는 점입니다.

**동작 원리:**
- 호출이 ClusterIP로 들어오면, 파드가 없더라도 커널의 `tcp_v4_connect` 진입부에서 목적지 IP를 포착
- eBPF가 ringbuf로 이벤트를 전송하고, 매핑 테이블이 Service/ClusterIP를 알고 있으므로 시계열 유지
- 파드가 0이어도 메트릭 시계열은 살아있고, rate/increase로 "최근 증가"만 트리거에 사용

**KEDA 연동:**
```yaml
# 파드 0개 상태에서도 트래픽 감지 시 자동 스케일업
spec:
  minReplicaCount: 0
  triggers:
    - type: prometheus
      metadata:
        query: sum(rate(internal_tcp_attempts_total{destination_service="my-svc"}[1m]))
        threshold: "1"
```

### 한계

- **Headless/Pod IP 직접 호출**: 파드가 0이면 IP가 없으므로 감지 불가 (ClusterIP 경로로 유도 필요)
- **HTTPS 트래픽**: TLS 암호화로 페이로드 파싱 불가 (L4 메트릭만 수집)
- **HTTP/2, gRPC**: 바이너리 프로토콜로 별도 파서 필요 (향후 확장)

---

## 메트릭 스키마

### L4 메트릭 (송신)
```text
internal_tcp_attempts_total{
  destination_namespace,
  destination_service,
  destination_pod,
  process_comm
}
```

### L7 메트릭 (수신)
```text
internal_http_requests_total{
  source_ip,
  destination_namespace,
  destination_service,
  destination_pod,
  method,
  path,
  process_comm
}
```

---

## 환경변수 설정

| 환경변수 | 기본값 | 설명 |
|---------|-------|------|
| `MODE` | `cluster` | 실행 모드 (cluster/local) |
| `METRICS_ADDR` | `0.0.0.0:9102` | 메트릭 서버 주소 |
| `WATCH_NAMESPACE` | (전체) | 감시 네임스페이스 |
| `MAPPER_TTL` | `60s` | 매핑 캐시 TTL |
| `MAPPER_CAPACITY` | `2048` | 매핑 테이블 최대 엔트리 |
| `EXCLUDE_COMMS` | `kubelet` | L4 제외 프로세스 (쉼표 구분) |
| `ENABLE_L4` | `true` | L4 TCP 감지 활성화 |
| `ENABLE_L7_HTTP` | `false` | L7 HTTP 감지 활성화 |
| `FILTER_HEALTHCHECK` | `true` | 헬스체크 경로 필터링 |
| `HEALTHCHECK_PATHS` | (내장 패턴) | 추가 헬스체크 경로 |
| `L7_EXCLUDE_COMMS` | `agent` | L7 제외 프로세스 (쉼표 구분) |

---

## 배포

### 빌드
```bash
cd ebpf
make build PUSH=true VERSION=0.1.0
```

### 배포
```bash
make deploy NAMESPACE=skuber-system
```

### 메트릭 확인
```bash
curl -s http://<nodeIP>:9102/metrics | grep internal_
```

---

## KEDA 예시

```yaml
apiVersion: keda.sh/v1alpha1
kind: ScaledObject
metadata:
  name: my-service-scaledobject
spec:
  scaleTargetRef:
    name: my-service
  minReplicaCount: 0
  maxReplicaCount: 10
  triggers:
    - type: prometheus
      metadata:
        serverAddress: http://prometheus:9090
        query: sum(rate(internal_tcp_attempts_total{destination_service="my-svc"}[1m]))
        threshold: "1"
```

---

## 기술 스택

| 구성 요소 | 기술 | 역할 |
|----------|------|------|
| 커널 감시자 | C + eBPF | TCP connect / HTTP read 캡처 |
| 유저스페이스 | Go | IP→Service 매핑, 메트릭 노출 |
| 저장소 | VictoriaMetrics/Prometheus | 메트릭 수집·쿼리 |
| 스케일러 | KEDA | 메트릭 기반 오토스케일링 |

---

## 향후 확장 방향

| 영역 | 계획 |
|------|------|
| **프로토콜 확장** | gRPC, HTTP/2, WebSocket 지원 |
| **보안 트래픽** | TLS 핸드셰이크 메타데이터 수집 (암호화 해제 없이) |
| **고급 분석** | 요청 레이턴시, 에러율 메트릭 추가 |
| **서비스 메시 연동** | Istio/Linkerd와의 보완적 통합 |

---

## 기술 성숙도

| 기능 | 상태 | 비고 |
|------|------|------|
| L4 TCP 감지 | ✅ Production Ready | 안정적 운영 중 |
| L7 HTTP 감지 | ✅ Production Ready | 헬스체크 필터링 포함 |
| K8s 메타데이터 매핑 | ✅ Production Ready | Service/Pod 자동 매핑 |
| Zero Scaling 지원 | ✅ Production Ready | KEDA 연동 검증 완료 |
| gRPC 지원 | 🚧 Planned | 향후 확장 예정 |
| HTTP/2 지원 | 🚧 Planned | 향후 확장 예정 |

---

## 라이선스

Dual BSD/GPL
