package main

import (
	"testing"
)

func TestHealthCheckFilter_NewHealthCheckFilter(t *testing.T) {
	tests := []struct {
		name           string
		enabled        bool
		customPatterns string
		wantEnabled    bool
		wantMinCount   int
	}{
		{
			name:           "enabled with defaults",
			enabled:        true,
			customPatterns: "",
			wantEnabled:    true,
			wantMinCount:   9, // default patterns count
		},
		{
			name:           "disabled",
			enabled:        false,
			customPatterns: "",
			wantEnabled:    false,
			wantMinCount:   9,
		},
		{
			name:           "with custom patterns",
			enabled:        true,
			customPatterns: "/custom-health,/app-status",
			wantEnabled:    true,
			wantMinCount:   11, // 9 defaults + 2 custom
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filter := NewHealthCheckFilter(tt.enabled, tt.customPatterns, false, "")

			if filter.enabled != tt.wantEnabled {
				t.Errorf("enabled = %v, want %v", filter.enabled, tt.wantEnabled)
			}

			if len(filter.patterns) < tt.wantMinCount {
				t.Errorf("got %d patterns, want at least %d", len(filter.patterns), tt.wantMinCount)
			}
		})
	}
}

func TestHealthCheckFilter_IsHealthCheck(t *testing.T) {
	filter := NewHealthCheckFilter(true, "/custom-health", false, "")

	tests := []struct {
		path string
		want bool
	}{
		// Default patterns
		{"/healthz", true},
		{"/readyz", true},
		{"/livez", true},
		{"/health", true},
		{"/ready", true},
		{"/live", true},
		{"/ping", true},
		{"/status", true},
		{"/_health", true},

		// With subpaths
		{"/healthz/live", true},
		{"/health/check", true},
		{"/status/ready", true},

		// Custom pattern
		{"/custom-health", true},
		{"/custom-health/deep", true},

		// Case insensitive
		{"/HEALTHZ", true},
		{"/Health", true},
		{"/PING", true},

		// Not health checks
		{"/api/users", false},
		{"/api/health-data", false}, // health is not prefix
		{"/v1/status-report", false},
		{"/", false},
		{"/api", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := filter.IsHealthCheck(tt.path)
			if got != tt.want {
				t.Errorf("IsHealthCheck(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestHealthCheckFilter_Disabled(t *testing.T) {
	filter := NewHealthCheckFilter(false, "", false, "")

	// When disabled, nothing should be considered a health check
	paths := []string{"/healthz", "/readyz", "/health", "/ping"}

	for _, path := range paths {
		if filter.IsHealthCheck(path) {
			t.Errorf("disabled filter should not match %q", path)
		}
	}
}

func TestHealthCheckFilter_Patterns(t *testing.T) {
	filter := NewHealthCheckFilter(true, "/custom1,/custom2", false, "")
	patterns := filter.Patterns()

	// Should include defaults + custom
	if len(patterns) < 11 {
		t.Errorf("got %d patterns, want at least 11", len(patterns))
	}

	// Check custom patterns are included
	customFound := 0
	for _, p := range patterns {
		if p == "/custom1" || p == "/custom2" {
			customFound++
		}
	}

	if customFound != 2 {
		t.Errorf("expected 2 custom patterns, found %d", customFound)
	}
}

func TestHealthCheckFilter_IsHealthCheckUA(t *testing.T) {
	filter := NewHealthCheckFilter(true, "", true, "custom-checker")

	tests := []struct {
		name      string
		userAgent string
		want      bool
	}{
		// 기본 패턴 매칭
		{"ALB health checker", "ELB-HealthChecker/2.0", true},
		{"kube-probe", "kube-probe/1.28", true},

		// 커스텀 패턴 매칭
		{"custom checker", "custom-checker/1.0", true},

		// 대소문자 무시
		{"ALB lowercase", "elb-healthchecker/2.0", true},
		{"kube-probe uppercase", "KUBE-PROBE/1.28", true},

		// 일반 User-Agent (매칭 안됨)
		{"Mozilla browser", "Mozilla/5.0", false},
		{"curl", "curl/7.68.0", false},
		{"Go HTTP client", "Go-http-client/1.1", false},

		// 빈 문자열
		{"empty string", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := filter.IsHealthCheckUA(tt.userAgent)
			if got != tt.want {
				t.Errorf("IsHealthCheckUA(%q) = %v, want %v", tt.userAgent, got, tt.want)
			}
		})
	}
}

func TestHealthCheckFilter_UADisabled(t *testing.T) {
	filter := NewHealthCheckFilter(true, "", false, "")

	// UA 필터 비활성화 시 매칭 안됨
	if filter.IsHealthCheckUA("ELB-HealthChecker/2.0") {
		t.Error("disabled UA filter should not match ELB-HealthChecker/2.0")
	}
	if filter.IsHealthCheckUA("kube-probe/1.28") {
		t.Error("disabled UA filter should not match kube-probe/1.28")
	}
}

func TestHealthCheckFilter_CombinedFiltering(t *testing.T) {
	filter := NewHealthCheckFilter(true, "", true, "")

	tests := []struct {
		name      string
		path      string
		userAgent string
		pathMatch bool
		uaMatch   bool
	}{
		{
			name:      "path only match",
			path:      "/healthz",
			userAgent: "Mozilla/5.0",
			pathMatch: true,
			uaMatch:   false,
		},
		{
			name:      "UA only match",
			path:      "/",
			userAgent: "ELB-HealthChecker/2.0",
			pathMatch: false,
			uaMatch:   true,
		},
		{
			name:      "both match",
			path:      "/healthz",
			userAgent: "kube-probe/1.28",
			pathMatch: true,
			uaMatch:   true,
		},
		{
			name:      "neither match",
			path:      "/api/users",
			userAgent: "Mozilla/5.0",
			pathMatch: false,
			uaMatch:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotPath := filter.IsHealthCheck(tt.path)
			gotUA := filter.IsHealthCheckUA(tt.userAgent)
			if gotPath != tt.pathMatch {
				t.Errorf("IsHealthCheck(%q) = %v, want %v", tt.path, gotPath, tt.pathMatch)
			}
			if gotUA != tt.uaMatch {
				t.Errorf("IsHealthCheckUA(%q) = %v, want %v", tt.userAgent, gotUA, tt.uaMatch)
			}
		})
	}
}

func TestHealthCheckFilter_UAPatterns(t *testing.T) {
	filter := NewHealthCheckFilter(true, "", true, "my-checker,test-probe")
	uaPatterns := filter.UAPatterns()

	// 기본 2개 + 커스텀 2개 = 4개
	if len(uaPatterns) != 4 {
		t.Errorf("got %d UA patterns, want 4", len(uaPatterns))
	}

	// 기본 패턴 확인
	defaultFound := 0
	for _, p := range uaPatterns {
		if p == "elb-healthchecker" || p == "kube-probe" {
			defaultFound++
		}
	}
	if defaultFound != 2 {
		t.Errorf("expected 2 default UA patterns, found %d", defaultFound)
	}

	// 커스텀 패턴 확인
	customFound := 0
	for _, p := range uaPatterns {
		if p == "my-checker" || p == "test-probe" {
			customFound++
		}
	}
	if customFound != 2 {
		t.Errorf("expected 2 custom UA patterns, found %d", customFound)
	}
}

func TestBytesToString(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
		want  string
	}{
		{
			name:  "null terminated",
			input: []byte{'h', 'e', 'l', 'l', 'o', 0, 'x', 'x'},
			want:  "hello",
		},
		{
			name:  "no null",
			input: []byte{'h', 'e', 'l', 'l', 'o'},
			want:  "hello",
		},
		{
			name:  "empty",
			input: []byte{0},
			want:  "",
		},
		{
			name:  "all null",
			input: []byte{0, 0, 0, 0},
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := bytesToString(tt.input)
			if got != tt.want {
				t.Errorf("bytesToString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestUint32ToIP(t *testing.T) {
	tests := []struct {
		name  string
		input uint32
		want  string
	}{
		{
			name:  "localhost",
			input: 0x7f000001, // 127.0.0.1 in big endian
			want:  "127.0.0.1",
		},
		{
			name:  "10.0.0.1",
			input: 0x0a000001,
			want:  "10.0.0.1",
		},
		{
			name:  "192.168.1.1",
			input: 0xc0a80101,
			want:  "192.168.1.1",
		},
		{
			name:  "zero",
			input: 0,
			want:  "0.0.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := uint32ToIP(tt.input)
			if got.String() != tt.want {
				t.Errorf("uint32ToIP(0x%x) = %s, want %s", tt.input, got.String(), tt.want)
			}
		})
	}
}
