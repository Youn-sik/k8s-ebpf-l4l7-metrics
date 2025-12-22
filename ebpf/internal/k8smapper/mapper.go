package k8smapper // K8s 매핑 로직 패키지

import (
	"context" // 컨텍스트 기반 종료/타임아웃 제어
	"log"     // 로그 출력
	"net"     // IP 파싱 및 DNS 조회
	"sync"    // 맵 보호용 락
	"time"    // TTL 관리

	corev1 "k8s.io/api/core/v1"           // Service 리소스 타입
	discoveryv1 "k8s.io/api/discovery/v1" // EndpointSlice 리소스 타입
	"k8s.io/apimachinery/pkg/util/sets"   // 중복 없는 셋
	"k8s.io/client-go/informers"          // 인포머 팩토리
	"k8s.io/client-go/kubernetes"         // 클라이언트셋
	"k8s.io/client-go/rest"               // in-cluster 설정
	"k8s.io/client-go/tools/cache"        // 리소스 이벤트 핸들러/캐시
	"k8s.io/client-go/tools/clientcmd"    // kubeconfig 로더
)

type ServiceMeta struct {
	Namespace string // 네임스페이스
	Service   string // 서비스명
	Pod       string // 포드명(옵션)
}

type entry struct {
	meta    ServiceMeta // 매핑된 메타데이터
	expires time.Time   // TTL 만료 시간
}

type Mapper struct {
	ttl      time.Duration // 엔트리 TTL
	capacity int           // 맵 용량 제한

	mu      sync.RWMutex     // 동시 접근 보호용 락
	cluster map[string]entry // ClusterIP -> ns/svc 매핑
	pods    map[string]entry // PodIP(또는 ExternalName 해석 IP) -> ns/svc/pod 매핑
}

type Options struct {
	Namespace string        // 빈 값이면 전체 네임스페이스 감시
	TTL       time.Duration // 엔트리 TTL
	Capacity  int           // 맵 용량 제한(0이면 제한 없음)
}

const (
	defaultTTL          = 60 * time.Second             // 기본 TTL
	defaultCapacity     = 2048                         // 기본 용량
	serviceNameLabelKey = "kubernetes.io/service-name" // EndpointSlice → Service 라벨 키
)

func NewMapper(opts Options) (*Mapper, error) {
	if opts.TTL == 0 { // TTL 미지정 시 기본값 사용
		opts.TTL = defaultTTL
	}
	if opts.Capacity == 0 { // 용량 미지정 시 기본값 사용
		opts.Capacity = defaultCapacity
	}
	return &Mapper{ // 맵과 설정 초기화
		ttl:      opts.TTL,
		capacity: opts.Capacity,
		cluster:  make(map[string]entry),
		pods:     make(map[string]entry),
	}, nil
}

func (m *Mapper) Run(ctx context.Context, opts Options, kubeconfigPath string) error {
	var (
		cfg *rest.Config
		err error
	)
	if kubeconfigPath != "" { // 로컬 kubeconfig 우선
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfigPath)
	} else { // 없으면 in-cluster
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return err // 설정 로드 실패
	}
	clientset, err := kubernetes.NewForConfig(cfg) // 클라이언트셋 생성
	if err != nil {                                // 실패 시 에러 반환
		return err
	}

	// TTL보다 짧은 주기로 resync하여 살아있는 엔트리를 갱신
	resyncPeriod := opts.TTL / 2
	if resyncPeriod <= 0 {
		resyncPeriod = defaultTTL / 2
	}

	factory := informers.NewSharedInformerFactoryWithOptions( // 인포머 팩토리 생성
		clientset,                               // 대상 클라이언트셋
		resyncPeriod,                            // 리싱크 주기
		informers.WithNamespace(opts.Namespace), // 네임스페이스 필터
	)

	svcInformer := factory.Core().V1().Services().Informer()            // Service 인포머
	epsInformer := factory.Discovery().V1().EndpointSlices().Informer() // EndpointSlice 인포머

	svcInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{ // Service 이벤트 핸들러
		AddFunc: func(obj interface{}) { // 추가
			m.onService(obj.(*corev1.Service))
		},
		UpdateFunc: func(_, newObj interface{}) { // 갱신
			m.onService(newObj.(*corev1.Service))
		},
		DeleteFunc: func(obj interface{}) { // 삭제
			if svc, ok := toService(obj); ok {
				m.onServiceDelete(svc)
			}
		},
	})

	epsInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{ // EndpointSlice 이벤트 핸들러
		AddFunc: func(obj interface{}) { // 추가
			m.onEndpointSlice(obj.(*discoveryv1.EndpointSlice))
		},
		UpdateFunc: func(_, newObj interface{}) { // 갱신
			m.onEndpointSlice(newObj.(*discoveryv1.EndpointSlice))
		},
		DeleteFunc: func(obj interface{}) { // 삭제
			if eps, ok := toEndpointSlice(obj); ok {
				m.onEndpointSliceDelete(eps)
			}
		},
	})

	factory.Start(ctx.Done())            // 인포머 시작
	factory.WaitForCacheSync(ctx.Done()) // 캐시 동기화 대기

	ticker := time.NewTicker(m.ttl) // TTL 만료 청소용 타이머
	defer ticker.Stop()             // 종료 시 타이머 해제

	for { // 메인 루프
		select {
		case <-ctx.Done(): // 종료 시그널
			return nil
		case <-ticker.C: // 주기적 청소
			m.pruneExpired()
		}
	}
}

func (m *Mapper) onService(svc *corev1.Service) {
	ns := svc.Namespace // 네임스페이스
	name := svc.Name    // 서비스명

	ips := sets.NewString()                  // ClusterIP 중복 제거용 셋
	for _, ip := range svc.Spec.ClusterIPs { // ClusterIPs 목록 순회
		ips.Insert(ip)
	}
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" { // 단일 ClusterIP 필드
		ips.Insert(svc.Spec.ClusterIP)
	}
	for ip := range ips { // 모든 ClusterIP 처리
		if net.ParseIP(ip) == nil || net.ParseIP(ip).To4() == nil { // IPv4만 허용
			continue
		}
		m.upsertCluster(ip, ServiceMeta{Namespace: ns, Service: name}) // ClusterIP 매핑 저장
	}

	if svc.Spec.Type == corev1.ServiceTypeExternalName && svc.Spec.ExternalName != "" { // ExternalName 처리
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)       // DNS 조회 타임아웃
		defer cancel()                                                                // 컨텍스트 해제
		addrs, err := net.DefaultResolver.LookupIP(ctx, "ip4", svc.Spec.ExternalName) // IPv4로 DNS 조회
		if err != nil {                                                               // 실패 시 로그
			log.Printf("externalName resolve failed ns=%s svc=%s host=%s err=%v", ns, name, svc.Spec.ExternalName, err)
		} else {
			for _, ip := range addrs { // 조회된 IP 반복
				m.upsertPod(ip.String(), ServiceMeta{Namespace: ns, Service: name}) // Pod 매핑에 추가
			}
		}
	}
}

func (m *Mapper) onServiceDelete(svc *corev1.Service) {
	m.mu.Lock()         // 쓰기 잠금
	defer m.mu.Unlock() // 해제 예약

	ips := sets.NewString()                  // ClusterIP 셋
	for _, ip := range svc.Spec.ClusterIPs { // ClusterIPs 순회
		ips.Insert(ip)
	}
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" { // 단일 ClusterIP 포함
		ips.Insert(svc.Spec.ClusterIP)
	}
	for ip := range ips { // 모든 IP 삭제
		delete(m.cluster, ip)
	}
}

func (m *Mapper) onEndpointSlice(eps *discoveryv1.EndpointSlice) {
	svcName := eps.Labels[serviceNameLabelKey] // 서비스명 라벨 추출
	if svcName == "" {                         // 없으면 무시
		return
	}
	ns := eps.Namespace                // 네임스페이스
	for _, ep := range eps.Endpoints { // 엔드포인트 순회
		for _, addr := range ep.Addresses { // 주소 순회
			parsed := net.ParseIP(addr)               // IP 파싱
			if parsed == nil || parsed.To4() == nil { // IPv4만 허용
				continue
			}
			podName := ""                                          // 기본 포드명
			if ep.TargetRef != nil && ep.TargetRef.Kind == "Pod" { // 포드 참조 있으면
				podName = ep.TargetRef.Name // 포드명 설정
			}
			m.upsertPod(addr, ServiceMeta{ // Pod 매핑 추가
				Namespace: ns,
				Service:   svcName,
				Pod:       podName,
			})
		}
	}
}

func (m *Mapper) onEndpointSliceDelete(eps *discoveryv1.EndpointSlice) {
	svcName := eps.Labels[serviceNameLabelKey] // 서비스명 라벨 추출
	if svcName == "" {                         // 없으면 무시
		return
	}
	ns := eps.Namespace                // 네임스페이스
	for _, ep := range eps.Endpoints { // 엔드포인트 순회
		for _, addr := range ep.Addresses { // 주소 순회
			parsed := net.ParseIP(addr)               // IP 파싱
			if parsed == nil || parsed.To4() == nil { // IPv4만 허용
				continue
			}
			m.mu.Lock()                                                                                 // 쓰기 잠금
			if ent, ok := m.pods[addr]; ok && ent.meta.Namespace == ns && ent.meta.Service == svcName { // 같은 서비스면
				delete(m.pods, addr) // 삭제
			}
			m.mu.Unlock() // 잠금 해제
		}
	}
}

func (m *Mapper) Lookup(ip string) (ServiceMeta, bool) {
	now := time.Now()                                           // 현재 시각
	m.mu.RLock()                                                // 읽기 잠금
	if ent, ok := m.cluster[ip]; ok && ent.expires.After(now) { // ClusterIP에서 유효 엔트리 찾기
		m.mu.RUnlock()
		return ent.meta, true
	}
	if ent, ok := m.pods[ip]; ok && ent.expires.After(now) { // PodIP에서 유효 엔트리 찾기
		m.mu.RUnlock()
		return ent.meta, true
	}
	m.mu.RUnlock()              // 잠금 해제
	return ServiceMeta{}, false // 미매칭
}

func (m *Mapper) upsertCluster(ip string, meta ServiceMeta) {
	m.mu.Lock()                                         // 쓰기 잠금
	defer m.mu.Unlock()                                 // 해제 예약
	if m.capacity > 0 && len(m.cluster) >= m.capacity { // 용량 초과 시 무시
		return
	}
	m.cluster[ip] = entry{meta: meta, expires: time.Now().Add(m.ttl)} // 엔트리 추가/갱신
}

func (m *Mapper) upsertPod(ip string, meta ServiceMeta) {
	m.mu.Lock()                                      // 쓰기 잠금
	defer m.mu.Unlock()                              // 해제 예약
	if m.capacity > 0 && len(m.pods) >= m.capacity { // 용량 초과 시 무시
		return
	}
	m.pods[ip] = entry{meta: meta, expires: time.Now().Add(m.ttl)} // 엔트리 추가/갱신
}

func (m *Mapper) pruneExpired() {
	now := time.Now()             // 현재 시각
	m.mu.Lock()                   // 쓰기 잠금
	for k, v := range m.cluster { // ClusterIP 엔트리 순회
		if v.expires.Before(now) { // 만료 확인
			delete(m.cluster, k) // 삭제
		}
	}
	for k, v := range m.pods { // PodIP 엔트리 순회
		if v.expires.Before(now) { // 만료 확인
			delete(m.pods, k) // 삭제
		}
	}
	m.mu.Unlock() // 잠금 해제
}

func toService(obj interface{}) (*corev1.Service, bool) {
	switch t := obj.(type) { // 타입 분기
	case *corev1.Service: // 직접 Service 타입
		return t, true
	case cache.DeletedFinalStateUnknown: // tombstone 래퍼
		if svc, ok := t.Obj.(*corev1.Service); ok { // 내부 객체가 Service인지 확인
			return svc, true
		}
	}
	return nil, false // 매칭 실패
}

func toEndpointSlice(obj interface{}) (*discoveryv1.EndpointSlice, bool) {
	switch t := obj.(type) { // 타입 분기
	case *discoveryv1.EndpointSlice: // 직접 EndpointSlice 타입
		return t, true
	case cache.DeletedFinalStateUnknown: // tombstone 래퍼
		if eps, ok := t.Obj.(*discoveryv1.EndpointSlice); ok { // 내부 객체가 EndpointSlice인지 확인
			return eps, true
		}
	}
	return nil, false // 매칭 실패
}
