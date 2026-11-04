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
