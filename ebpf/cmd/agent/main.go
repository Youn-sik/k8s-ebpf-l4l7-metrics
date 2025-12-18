package main // 메인 실행 진입점 패키지

import (
	"context"         // 종료 제어용 컨텍스트
	"encoding/binary" // 바이트 오더 변환
	"errors"          // 에러 비교 유틸
	"log"             // 표준 로그 출력
	"net"             // IP 타입 변환
	"os"              // 환경변수 읽기
	"os/signal"       // OS 시그널 수신
	"strconv"         // 문자열 숫자 변환
	"syscall"         // 시그널 상수 제공
	"time"            // TTL 파싱

	// 엔디안 판별용 포인터 캐스팅
	ebpfobjs "ebpf-k8s-internal-traffic-metrics" // bpf2go가 생성한 오브젝트 래퍼

	"github.com/cilium/ebpf/link"    // eBPF 프로그램을 커널의 특정 훅에 연결하고 연결을 관리하는 패키지
	"github.com/cilium/ebpf/ringbuf" // eBPF 프로그램이 커널에서 발생시킨 이벤트를 User Space 에서 비동기적으로 수신하는 통로
	"github.com/cilium/ebpf/rlimit"  // eBPF 프로그램 로딩에 필요한 시스템 자원 제한을 자동으로 설정하는 유틸리티

	"ebpf-k8s-internal-traffic-metrics/internal/k8smapper" // K8s 매핑
)

type event struct {
	Daddr uint32 // 목적지 IPv4 (네트워크 바이트 오더)
}

const eventSize = 4 // 이벤트 페이로드 크기

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds) // 로그에 날짜+마이크로초 포함

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM) // SIGINT/SIGTERM 수신 컨텍스트
	defer stop()                                                                             // 시그널 리스너 정리

	mapperOpts := k8smapper.Options{ // 매퍼 옵션 구성
		Namespace: os.Getenv("WATCH_NAMESPACE"), // 감시 네임스페이스(없으면 전체)
	}
	if ttlStr := os.Getenv("MAPPER_TTL"); ttlStr != "" { // TTL 설정
		if d, err := time.ParseDuration(ttlStr); err == nil {
			mapperOpts.TTL = d
		} else {
			log.Printf("invalid MAPPER_TTL=%s, using default: %v", ttlStr, err)
		}
	}
	if capStr := os.Getenv("MAPPER_CAPACITY"); capStr != "" { // 용량 설정
		if v, err := strconv.Atoi(capStr); err == nil && v > 0 {
			mapperOpts.Capacity = v
		} else {
			log.Printf("invalid MAPPER_CAPACITY=%s, using default: %v", capStr, err)
		}
	}

	mapper, err := k8smapper.NewMapper(mapperOpts) // 매퍼 생성
	if err != nil {
		log.Fatalf("failed to create mapper: %v", err)
	}
	go func() { // 매퍼 실행 고루틴
		if runErr := mapper.Run(ctx, mapperOpts); runErr != nil {
			log.Fatalf("mapper run failed: %v", runErr)
		}
	}()

	if err := rlimit.RemoveMemlock(); err != nil { // memlock 제한 해제 시도
		log.Fatalf("failed to adjust memlock rlimit: %v", err) // 실패 시 프로그램 종료
	}

	var objs ebpfobjs.TcpConnectObjects                                // eBPF 오브젝트 컨테이너
	if err := ebpfobjs.LoadTcpConnectObjects(&objs, nil); err != nil { // eBPF 오브젝트 로드
		log.Fatalf("failed to load BPF objects: %v", err) // 로드 실패 시 종료
	}
	defer objs.Close() // 리소스 해제 예약

	kp, err := link.Kprobe("tcp_v4_connect", objs.TcpV4ConnectEnter, nil) // tcp_v4_connect에 kprobe 부착
	if err != nil {                                                       // 부착 실패 처리
		log.Fatalf("failed to attach kprobe: %v", err) // 치명적 오류
	}
	defer kp.Close() // kprobe 해제 예약

	rd, err := ringbuf.NewReader(objs.Events) // 링버퍼 리더 생성
	if err != nil {                           // 리더 생성 실패 처리
		log.Fatalf("failed to create ringbuf reader: %v", err) // 치명적 오류
	}
	defer rd.Close() // 리더 닫기 예약

	log.Println("tcpconnect agent started; waiting for events") // 에이전트 시작 로그

	go func() { // 종료 시 읽기 차단 해제용 고루틴
		<-ctx.Done() // 시그널 대기
		rd.Close()   // 리더 닫아 Read 해제
	}()

	for {
		record, err := rd.Read() // 링버퍼에서 이벤트 읽기
		if err != nil {          // 읽기 실패 처리
			if errors.Is(err, ringbuf.ErrClosed) { // 리더가 닫힌 경우
				log.Println("ringbuf reader closed; exiting") // 종료 로그
				return                                        // 프로그램 종료
			}
			log.Printf("ringbuf read error: %v", err) // 기타 읽기 오류 기록
			continue                                  // 다음 이벤트로 진행
		}

		if len(record.RawSample) < eventSize { // 페이로드 길이 검사
			log.Printf("ringbuf decode error: short sample (%d bytes, want %d)", len(record.RawSample), eventSize) // 짧은 샘플 오류
			continue                                                                                               // 다음 이벤트
		}

		addr := binary.BigEndian.Uint32(record.RawSample[:eventSize]) // 커널에서 네트워크 오더로 저장된 u32를 읽음

		ip := make(net.IP, net.IPv4len)      // IPv4 버퍼 생성
		binary.BigEndian.PutUint32(ip, addr) // 네트워크 오더로 IP 채우기

		if meta, ok := mapper.Lookup(ip.String()); ok { // 매핑 성공 시 메타 포함
			log.Printf("tcp connect dest=%s ns=%s svc=%s pod=%s", ip.String(), meta.Namespace, meta.Service, meta.Pod)
		} else {
			log.Printf("tcp connect dest=%s (unmapped)", ip.String()) // 매핑 실패 로그
		}
	}
}
