package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"k8s-ebpf-l4l7-metrics/internal/k8smapper"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	cfg := loadConfig()

	log.Printf("[CONFIG] mode=%s, metricsAddr=%s", cfg.Mode, cfg.MetricsAddr)
	log.Printf("[CONFIG] L4 enabled=%t, L7 enabled=%t", cfg.EnableL4, cfg.EnableL7)

	// ==========================================================================
	// K8s Mapper
	// ==========================================================================

	mapper, err := k8smapper.NewMapper(cfg.MapperOpts)
	if err != nil {
		log.Fatalf("failed to create mapper: %v", err)
	}

	go func() {
		var kubeconfigPath string
		if cfg.Mode == "local" {
			if home, herr := os.UserHomeDir(); herr == nil {
				kubeconfigPath = filepath.Join(home, ".kube", "config")
			}
		}
		if runErr := mapper.Run(ctx, cfg.MapperOpts, kubeconfigPath); runErr != nil {
			log.Fatalf("mapper run failed: %v", runErr)
		}
	}()

	// ==========================================================================
	// Prometheus Metrics
	// ==========================================================================

	l4Counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "internal_tcp_attempts_total",
			Help: "Count of internal TCP connect attempts mapped to K8s Services/Pods",
		},
		[]string{"destination_namespace", "destination_service", "destination_pod", "process_comm"},
	)
	if err := prometheus.Register(l4Counter); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			l4Counter = are.ExistingCollector.(*prometheus.CounterVec)
		} else {
			log.Fatalf("failed to register L4 metrics: %v", err)
		}
	}

	l7Counter := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "internal_http_requests_total",
			Help: "Count of HTTP requests to Pods (healthcheck excluded)",
		},
		[]string{
			"source_ip",
			"destination_namespace",
			"destination_service",
			"destination_pod",
			"method",
			"path",
			"process_comm",
		},
	)
	if err := prometheus.Register(l7Counter); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok {
			l7Counter = are.ExistingCollector.(*prometheus.CounterVec)
		} else {
			log.Fatalf("failed to register L7 metrics: %v", err)
		}
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	srv := &http.Server{
		Addr:    cfg.MetricsAddr,
		Handler: mux,
	}
	go func() {
		log.Printf("[METRICS] server listening on %s", cfg.MetricsAddr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("metrics server failed: %v", err)
		}
	}()

	// ==========================================================================
	// eBPF Setup
	// ==========================================================================

	if err := rlimit.RemoveMemlock(); err != nil {
		log.Fatalf("failed to adjust memlock rlimit: %v", err)
	}

	if cfg.EnableL4 {
		log.Println("[L4] Loading eBPF objects...")
		var l4Objs L4SenderObjects
		if err := LoadL4SenderObjects(&l4Objs, nil); err != nil {
			log.Fatalf("[L4] failed to load BPF objects: %v", err)
		}
		defer l4Objs.Close()

		kp, err := link.Kprobe("tcp_v4_connect", l4Objs.TcpV4ConnectEnter, nil)
		if err != nil {
			log.Fatalf("[L4] failed to attach kprobe: %v", err)
		}
		defer kp.Close()

		l4Reader, err := ringbuf.NewReader(l4Objs.L4Events)
		if err != nil {
			log.Fatalf("[L4] failed to create ringbuf reader: %v", err)
		}

		l4Filter := NewL4Filter(cfg.ExcludeComms)
		l4Handler := NewL4Handler(l4Reader, mapper, l4Counter, l4Filter)

		go func() {
			<-ctx.Done()
			l4Handler.Close()
		}()
		go l4Handler.Run(ctx)
	}

	if cfg.EnableL7 {
		log.Println("[L7] Loading eBPF objects...")
		var l7Objs L7ReceiverObjects
		if err := LoadL7ReceiverObjects(&l7Objs, nil); err != nil {
			log.Printf("[L7] WARNING: failed to load BPF objects, L7 disabled: %v", err)
		} else {
			defer l7Objs.Close()
			log.Println("[L7] BPF objects loaded successfully")

			tpAcceptEnter, _ := link.Tracepoint("syscalls", "sys_enter_accept4", l7Objs.SysEnterAccept4, nil)
			defer func() { if tpAcceptEnter != nil { tpAcceptEnter.Close() } }()

			tpAcceptExit, _ := link.Tracepoint("syscalls", "sys_exit_accept4", l7Objs.SysExitAccept4, nil)
			defer func() { if tpAcceptExit != nil { tpAcceptExit.Close() } }()

			kretAccept, _ := link.Kretprobe("inet_csk_accept", l7Objs.KretprobeInetCskAccept, nil)
			defer func() { if kretAccept != nil { kretAccept.Close() } }()

			tpReadEnter, _ := link.Tracepoint("syscalls", "sys_enter_read", l7Objs.SysEnterRead, nil)
			defer func() { if tpReadEnter != nil { tpReadEnter.Close() } }()

			tpReadExit, _ := link.Tracepoint("syscalls", "sys_exit_read", l7Objs.SysExitRead, nil)
			defer func() { if tpReadExit != nil { tpReadExit.Close() } }()

			tpClose, _ := link.Tracepoint("syscalls", "sys_enter_close", l7Objs.SysEnterClose, nil)
			defer func() { if tpClose != nil { tpClose.Close() } }()

			l7Reader, err := ringbuf.NewReader(l7Objs.HttpEvents)
			if err != nil {
				log.Printf("[L7] failed to create ringbuf reader: %v", err)
			} else {
				healthFilter := NewHealthCheckFilter(cfg.FilterHealthCheck, cfg.HealthCheckPaths, cfg.FilterHealthCheckUA, cfg.HealthCheckUserAgents)
				processFilter := NewL7ProcessFilter(cfg.L7ExcludeComms)
				l7Handler := NewL7Handler(l7Reader, mapper, l7Counter, healthFilter, processFilter)

				go func() {
					<-ctx.Done()
					l7Handler.Close()
				}()
				go l7Handler.Run(ctx)
			}
		}
	}

	log.Println("[MAIN] Agent started successfully")
	<-ctx.Done()

	log.Println("[MAIN] Shutting down...")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = srv.Shutdown(shutdownCtx)
	log.Println("[MAIN] Agent stopped")
}

type Config struct {
	Mode                  string
	MetricsAddr           string
	MapperOpts            k8smapper.Options
	EnableL4              bool
	EnableL7              bool
	ExcludeComms          string
	FilterHealthCheck     bool
	HealthCheckPaths      string
	FilterHealthCheckUA   bool
	HealthCheckUserAgents string
	L7ExcludeComms        string
}

func loadConfig() Config {
	cfg := Config{
		Mode:                  getEnvDefault("MODE", "cluster"),
		MetricsAddr:           getEnvDefault("METRICS_ADDR", "0.0.0.0:9102"),
		EnableL4:              getEnvBool("ENABLE_L4", true),
		EnableL7:              getEnvBool("ENABLE_L7_HTTP", false),
		ExcludeComms:          os.Getenv("EXCLUDE_COMMS"),
		FilterHealthCheck:     getEnvBool("FILTER_HEALTHCHECK", true),
		HealthCheckPaths:      os.Getenv("HEALTHCHECK_PATHS"),
		FilterHealthCheckUA:   getEnvBool("FILTER_HEALTHCHECK_UA", true),
		HealthCheckUserAgents: os.Getenv("HEALTHCHECK_USER_AGENTS"),
		L7ExcludeComms:        os.Getenv("L7_EXCLUDE_COMMS"),
	}

	cfg.MapperOpts = k8smapper.Options{
		Namespace: os.Getenv("WATCH_NAMESPACE"),
	}

	if ttlStr := os.Getenv("MAPPER_TTL"); ttlStr != "" {
		if d, err := time.ParseDuration(ttlStr); err == nil {
			cfg.MapperOpts.TTL = d
		}
	}

	if capStr := os.Getenv("MAPPER_CAPACITY"); capStr != "" {
		if v, err := strconv.Atoi(capStr); err == nil && v > 0 {
			cfg.MapperOpts.Capacity = v
		}
	}

	return cfg
}

func getEnvDefault(key, defaultVal string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return defaultVal
}

func getEnvBool(key string, defaultVal bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return defaultVal
	}
	return v == "true" || v == "1" || v == "yes"
}
