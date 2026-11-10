package edge

import (
	"testing"
	"time"
)

func TestConfigFromGetterDefaults(t *testing.T) {
	cfg := ConfigFromGetter(func(string) string { return "" })
	if cfg.Listen != DefaultListen || cfg.AdminURL != DefaultAdminURL {
		t.Fatalf("listen/admin defaults = %+v", cfg)
	}
	if cfg.NodeAddr != DefaultNodeAddr || cfg.ChainAddr != DefaultChainAddr {
		t.Fatalf("backend defaults = %+v", cfg)
	}
	if cfg.MetricsListen != DefaultMetricsListen || cfg.VLESSUUID != "" {
		t.Fatalf("metrics/uuid defaults = %+v", cfg)
	}
	if cfg.DirectPath != DefaultDirectPath || cfg.ChainPath != DefaultChainPath || cfg.ResiPath != DefaultResiPath {
		t.Fatalf("path defaults = %+v", cfg)
	}
	if cfg.IdleTimeout != time.Duration(DefaultIdleTimeoutMS)*time.Millisecond {
		t.Fatalf("IdleTimeout = %v", cfg.IdleTimeout)
	}
	if cfg.DialTimeout != time.Duration(DefaultDialTimeoutMS)*time.Millisecond {
		t.Fatalf("DialTimeout = %v", cfg.DialTimeout)
	}
}

func TestConfigFromGetterOverrides(t *testing.T) {
	values := map[string]string{
		"EDGE_LISTEN":          "127.0.0.1:13000",
		"EDGE_ADMIN":           "http://127.0.0.1:13001",
		"EDGE_NODE":            "127.0.0.1:18080",
		"EDGE_CHAIN":           "127.0.0.1:18082",
		"EDGE_METRICS_LISTEN":  "127.0.0.1:39003",
		"VLESS_UUID":           "uuid-123",
		"VLESS_DIRECT_PATH":    "/node",
		"VLESS_CHAIN_PATH":     "/chain",
		"RESI_PATH":            "/resi",
		"EDGE_IDLE_TIMEOUT_MS": "1500",
		"EDGE_DIAL_TIMEOUT_MS": "250",
	}
	cfg := ConfigFromGetter(func(key string) string { return values[key] })
	if cfg.Listen != "127.0.0.1:13000" || cfg.AdminURL != "http://127.0.0.1:13001" {
		t.Fatalf("listen/admin = %+v", cfg)
	}
	if cfg.NodeAddr != "127.0.0.1:18080" || cfg.ChainAddr != "127.0.0.1:18082" {
		t.Fatalf("backends = %+v", cfg)
	}
	if cfg.MetricsListen != "127.0.0.1:39003" || cfg.VLESSUUID != "uuid-123" {
		t.Fatalf("metrics/uuid = %+v", cfg)
	}
	if cfg.DirectPath != "/node" || cfg.ChainPath != "/chain" || cfg.ResiPath != "/resi" {
		t.Fatalf("paths = %+v", cfg)
	}
	if cfg.IdleTimeout != 1500*time.Millisecond || cfg.DialTimeout != 250*time.Millisecond {
		t.Fatalf("timeouts = %v/%v", cfg.IdleTimeout, cfg.DialTimeout)
	}
}

func TestConfigFromGetterInvalidTimeoutsFallBack(t *testing.T) {
	values := map[string]string{
		"EDGE_IDLE_TIMEOUT_MS": "nope",
		"EDGE_DIAL_TIMEOUT_MS": "-5",
	}
	cfg := ConfigFromGetter(func(key string) string { return values[key] })
	if cfg.IdleTimeout != time.Duration(DefaultIdleTimeoutMS)*time.Millisecond {
		t.Fatalf("IdleTimeout = %v", cfg.IdleTimeout)
	}
	if cfg.DialTimeout != time.Duration(DefaultDialTimeoutMS)*time.Millisecond {
		t.Fatalf("DialTimeout = %v", cfg.DialTimeout)
	}
}

func TestConfigFromGetterResourceDefaults(t *testing.T) {
	cfg := ConfigFromGetter(func(string) string { return "" })
	if cfg.MaxTunnels != DefaultMaxTunnels {
		t.Fatalf("MaxTunnels = %d, want %d", cfg.MaxTunnels, DefaultMaxTunnels)
	}
	if cfg.MaxConns != DefaultMaxConns {
		t.Fatalf("MaxConns = %d, want %d", cfg.MaxConns, DefaultMaxConns)
	}
	if cfg.ReadHeaderTimeout != time.Duration(DefaultReadHeaderTimeoutMS)*time.Millisecond {
		t.Fatalf("ReadHeaderTimeout = %v", cfg.ReadHeaderTimeout)
	}
	if cfg.MaxHeaderBytes != DefaultMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", cfg.MaxHeaderBytes, DefaultMaxHeaderBytes)
	}
}

func TestConfigFromGetterResourceOverrides(t *testing.T) {
	values := map[string]string{
		"EDGE_MAX_TUNNELS":            "64",
		"EDGE_MAX_CONNS":              "2048",
		"EDGE_READ_HEADER_TIMEOUT_MS": "2500",
		"EDGE_MAX_HEADER_BYTES":       "65536",
		"EDGE_ADMIN_ALLOW_REMOTE":     "1",
	}
	cfg := ConfigFromGetter(func(key string) string { return values[key] })
	if cfg.MaxTunnels != 64 || cfg.ReadHeaderTimeout != 2500*time.Millisecond || cfg.MaxHeaderBytes != 65536 {
		t.Fatalf("resource overrides = %+v", cfg)
	}
	if cfg.MaxConns != 2048 || !cfg.AllowRemoteAdmin {
		t.Fatalf("conn/admin overrides = %+v", cfg)
	}
}

func TestConfigFromGetterClampsResourceLimits(t *testing.T) {
	values := map[string]string{
		"EDGE_MAX_TUNNELS":      "999999",
		"EDGE_MAX_HEADER_BYTES": "999999999",
	}
	cfg := ConfigFromGetter(func(key string) string { return values[key] })
	if cfg.MaxTunnels != MaxMaxTunnels {
		t.Fatalf("MaxTunnels = %d, want %d", cfg.MaxTunnels, MaxMaxTunnels)
	}
	if cfg.MaxHeaderBytes != MaxMaxHeaderBytes {
		t.Fatalf("MaxHeaderBytes = %d, want %d", cfg.MaxHeaderBytes, MaxMaxHeaderBytes)
	}
	if cfg.MaxConns != DefaultMaxConns {
		t.Fatalf("MaxConns = %d, want default %d", cfg.MaxConns, DefaultMaxConns)
	}

	cfg = ConfigFromGetter(func(key string) string {
		if key == "EDGE_MAX_TUNNELS" {
			return "0"
		}
		return ""
	})
	if cfg.MaxTunnels != MinMaxTunnels {
		t.Fatalf("MaxTunnels = %d, want %d", cfg.MaxTunnels, MinMaxTunnels)
	}
}

func TestValidateConfigAcceptsDefaults(t *testing.T) {
	if err := ValidateConfig(ConfigFromGetter(func(string) string { return "" })); err != nil {
		t.Fatalf("ValidateConfig(defaults) = %v", err)
	}
	cfg := ConfigFromGetter(func(string) string { return "" })
	cfg.MetricsListen = "localhost:39002"
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig(localhost metrics) = %v", err)
	}
}

func TestValidateConfigRejectsBadPaths(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Config)
	}{
		{name: "relative", mutate: func(cfg *Config) { cfg.DirectPath = "ws-node" }},
		{name: "dotdot", mutate: func(cfg *Config) { cfg.ChainPath = "/ws/../node" }},
		{name: "whitespace", mutate: func(cfg *Config) { cfg.ResiPath = "/ws resi" }},
		{name: "query", mutate: func(cfg *Config) { cfg.ResiPath = "/ws-resi?x=1" }},
		{name: "root", mutate: func(cfg *Config) { cfg.DirectPath = "/" }},
		{name: "duplicate", mutate: func(cfg *Config) { cfg.ResiPath = cfg.DirectPath }},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			cfg := ConfigFromGetter(func(string) string { return "" })
			test.mutate(&cfg)
			if err := ValidateConfig(cfg); err == nil {
				t.Fatalf("ValidateConfig accepted invalid paths: %+v", cfg)
			}
		})
	}
}

func TestValidateConfigRejectsPortZeroAndListenerConflict(t *testing.T) {
	base := ConfigFromGetter(func(string) string { return "" })

	zeroListen := base
	zeroListen.Listen = "0.0.0.0:0"
	if err := ValidateConfig(zeroListen); err == nil {
		t.Fatal("ValidateConfig accepted EDGE_LISTEN port 0")
	}

	zeroMetrics := base
	zeroMetrics.MetricsListen = "127.0.0.1:0"
	if err := ValidateConfig(zeroMetrics); err == nil {
		t.Fatal("ValidateConfig accepted EDGE_METRICS_LISTEN port 0")
	}

	conflict := base
	conflict.Listen = "127.0.0.1:39002"
	conflict.MetricsListen = "127.0.0.1:39002"
	if err := ValidateConfig(conflict); err == nil {
		t.Fatal("ValidateConfig accepted identical public and metrics listeners")
	}

	wildcardConflict := base
	wildcardConflict.Listen = "0.0.0.0:39002"
	wildcardConflict.MetricsListen = "127.0.0.1:39002"
	if err := ValidateConfig(wildcardConflict); err == nil {
		t.Fatal("ValidateConfig accepted a wildcard public listener overlapping the metrics port")
	}

	badBackend := base
	badBackend.NodeAddr = "not-an-address"
	if err := ValidateConfig(badBackend); err == nil {
		t.Fatal("ValidateConfig accepted an invalid EDGE_NODE")
	}

	outOfRange := base
	outOfRange.MaxTunnels = MaxMaxTunnels + 1
	if err := ValidateConfig(outOfRange); err == nil {
		t.Fatal("ValidateConfig accepted an out-of-range EDGE_MAX_TUNNELS")
	}

	badConns := base
	badConns.MaxConns = MaxMaxConns + 1
	if err := ValidateConfig(badConns); err == nil {
		t.Fatal("ValidateConfig accepted an out-of-range EDGE_MAX_CONNS")
	}
}

func TestValidateAdminHost(t *testing.T) {
	for _, host := range []string{"localhost", "LOCALHOST", "127.0.0.1", "127.8.9.10", "::1"} {
		if err := ValidateAdminHost(host); err != nil {
			t.Fatalf("ValidateAdminHost(%q) = %v", host, err)
		}
	}
	for _, host := range []string{"", "0.0.0.0", "192.0.2.1", "203.0.113.5", "example.com", "::"} {
		if err := ValidateAdminHost(host); err == nil {
			t.Fatalf("ValidateAdminHost(%q) accepted a non-loopback host", host)
		}
	}
}
