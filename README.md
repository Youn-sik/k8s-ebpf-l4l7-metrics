## Zero Watchdog: 내부 트래픽 감지 파이프라인

**목표:** 파드가 0개일 때도 내부 TCP 연결 시도를 놓치지 않고 포착해 KEDA로 스케일 신호를 보내는 초경량 에이전트.

---

## 전체 흐름 (L4 TCP 기준)

1) **사전 준비 — Mapping (Go)**
- 역할: 어떤 IP가 어떤 Service인지 미리 학습.
- 동작: Go 에이전트가 Kubernetes API를 지속 감시해 새 Service와 ClusterIP를 메모리 맵에 기록.

2) **연결 포착 — Interception (C/eBPF)**
- 상황: Service A(Client) -> Service B(Server, 파드 0개) 호출.
- 동작: `tcp_v4_connect` 진입 시 eBPF Kprobe가 목적지 IP를 캡처하고 RingBuffer로 Go 에이전트에 전달.

3) **메트릭 변환 — Translation (Go)**
- 역할: 캡처한 IP를 서비스 이름으로 매핑 후 메트릭화.
- 동작: RingBuffer에서 IP를 읽고 메모리 맵으로 식별 후 Prometheus 카운터 증가:
  `internal_tcp_attempts_total{service="my-backend"} += 1`

4) **스케일 트리거 — Triggering (Victoria Metrics Agent + KEDA)**
- VM Single이 `/metrics`를 15초마다 스크랩 후 DB에 저장.
- KEDA가 쿼리:
  ```promql
  rate(internal_tcp_attempts_total{service="my-backend"}[1m])
  ```
- 증가가 감지되면 KEDA가 `my-backend` 파드를 `0 -> 1`로 스케일.

---

## 기술 스택과 역할

| 구성 요소 | 기술 스택 | 핵심 역할 | 비유 |
| --- | --- | --- | --- |
| 커널 감시자 | C + eBPF | TCP connect 시 목적지 IP 캡처 | CCTV (차량 번호판 촬영) |
| 통역사 | Go (User Space) | IP를 K8s Service로 변환, 메트릭 노출 | 관제 센터 (번호판 조회) |
| 저장소 | VM Single | 메트릭 수집·Rate 계산 제공 | 기록 보관소 |
| 실행자 | KEDA | 메트릭을 보고 파드 기동 | 현장 출동팀 |

---

## 왜 가볍고 확실한가

- 가벼움: L4 IP만 확인해 CPU/메모리 사용이 매우 적음(약 20MB 예상).
- 확실함: 파드가 0개라 패킷이 Drop돼도 커널 함수 진입부에서 100% 포착.
- 독립성: 무거운 사이드카 없이 이 기능만 수행하는 전용 에이전트.

이 구성을 통해 **초경량 에이전트 → VM Single → KEDA**로 이어지는 내부 트래픽 감지 파이프라인을 완성합니다.
