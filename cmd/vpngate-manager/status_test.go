package main

import (
	"testing"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/singbox"
)

func baseConfig(t *testing.T) Config {
	t.Helper()
	cfg, err := LoadConfig(envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func TestStatusSnapshotBaseline(t *testing.T) {
	cfg := baseConfig(t)
	manager := NewManager(cfg)
	snapshot := manager.StatusSnapshot()

	for _, key := range []string{
		"endpoints", "countries", "preferred_tag", "backup_tag", "auto_pinned",
		"refresh_history", "refresh_ok", "refresh_fail", "last_refresh",
		"last_error", "started_at", "proxy", "traffic", "full_probe",
		"refresh_job", "probe", "verify", "tunnel", "vless", "chain_switch",
		"resi", "pin_health", "threads", "cpu", "memory", "uptime_seconds",
	} {
		if _, ok := snapshot[key]; !ok {
			t.Fatalf("missing status key %q", key)
		}
	}
	if endpoints, ok := snapshot["endpoints"].([]any); !ok || len(endpoints) != 0 {
		t.Fatalf("endpoints = %#v", snapshot["endpoints"])
	}
	if snapshot["preferred_tag"] != nil || snapshot["backup_tag"] != nil {
		t.Fatalf("pins = %#v", snapshot)
	}
	if snapshot["proxy"] != "127.0.0.1:40000" {
		t.Fatalf("proxy = %v", snapshot["proxy"])
	}
	resi := snapshot["resi"].(map[string]any)
	if resi["enabled"] != false || len(resi) != 1 {
		t.Fatalf("disabled resi = %#v", resi)
	}
	pinHealth := snapshot["pin_health"].(map[string]any)
	if pinHealth["state"] != "unknown" {
		t.Fatalf("pin_health = %#v", pinHealth)
	}
	if snapshot["vless"] != nil {
		t.Fatalf("vless = %#v", snapshot["vless"])
	}
	if _, err := time.Parse("2006-01-02T15:04:05Z", snapshot["started_at"].(string)); err != nil {
		t.Fatalf("started_at: %v", err)
	}
	if snapshot["uptime_seconds"].(int64) < 0 {
		t.Fatalf("uptime = %v", snapshot["uptime_seconds"])
	}
	traffic := snapshot["traffic"].(map[string]any)
	if traffic["connections"] != 0 || traffic["bytes_up"] != 0 || traffic["bytes_down"] != 0 {
		t.Fatalf("traffic = %#v", traffic)
	}
}

func TestStatusSnapshotGatewayResi(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Resi = &singbox.ResiOutbound{Server: "192.0.2.10", ServerPort: 1080, Username: "u", Password: "p"}
	cfg.ResiSessionTTL = 300
	cfg.ResiPath = "/ws-resi"
	cfg.VLESSUUID = "uuid"
	snapshot := NewManager(cfg).StatusSnapshot()
	resi := snapshot["resi"].(map[string]any)
	// TTL alone is not sticky: the template must actually carry {session}.
	if resi["enabled"] != true || resi["mode"] != "rotation" {
		t.Fatalf("resi = %#v", resi)
	}
	if resi["host"] != "192.0.2.x" || resi["port"] != 1080 || resi["sticky_ttl"] != 300 {
		t.Fatalf("resi = %#v", resi)
	}
	if resi["mux_limit"] != 80 || resi["throttled"] != 0 {
		t.Fatalf("resi caps = %#v", resi)
	}
	vless := snapshot["vless"].(map[string]any)
	if vless["uuid"] != "uuid" {
		t.Fatalf("vless = %#v", vless)
	}
}

func TestStatusSnapshotRotateAndClash(t *testing.T) {
	cfg := baseConfig(t)
	cfg.VLESSUUID = "uuid"
	cfg.ResiRotate = true
	cfg.ClashAPIPort = 9090
	cfg.ResiPort = 8084
	cfg.ResiPath = "/ws-resi"
	snapshot := NewManager(cfg).StatusSnapshot()
	resi := snapshot["resi"].(map[string]any)
	if resi["enabled"] != true || resi["mode"] != "rotate" || resi["listen"] != "0.0.0.0" {
		t.Fatalf("resi = %#v", resi)
	}
	for _, key := range []string{"nodes", "cursor", "inbounds", "pool", "down"} {
		if resi[key] != 0 {
			t.Fatalf("resi[%s] = %v", key, resi[key])
		}
	}
	chain := snapshot["chain_switch"].(map[string]any)
	if chain["mode"] != "clash" || chain["clash_port"] != 9090 {
		t.Fatalf("chain = %#v", chain)
	}
}

func TestStatusSnapshotStickyRequiresSessionTemplate(t *testing.T) {
	cfg := baseConfig(t)
	cfg.Resi = &singbox.ResiOutbound{Server: "gateway.example", ServerPort: 1080, Username: "u", Password: "p"}
	cfg.ResiSessionTTL = 300
	cfg.ResiTemplate = "{user}-{session}"
	cfg.ResiPath = "/ws-resi"
	resi := NewManager(cfg).StatusSnapshot()["resi"].(map[string]any)
	if resi["mode"] != "sticky" {
		t.Fatalf("mode = %v", resi["mode"])
	}
	if resi["host"] != "gateway.example" {
		t.Fatalf("hostname must stay unmasked: %v", resi["host"])
	}
}

func TestStatusSnapshotMaskHost(t *testing.T) {
	cases := map[string]string{
		"192.0.2.10":      "192.0.2.x",
		"2001:db8::1":     "2001:db8::x",
		"gateway.example": "gateway.example",
		"":                "",
	}
	for input, want := range cases {
		if got := maskHost(input); got != want {
			t.Fatalf("maskHost(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestStatusSnapshotMuxCapMatchesPython(t *testing.T) {
	for _, test := range []struct{ mux, want int }{
		{2, 1}, {3, 2}, {4, 3}, {5, 4}, {100, 80},
	} {
		cfg := baseConfig(t)
		cfg.MaxMuxConnections = test.mux
		cfg.Resi = &singbox.ResiOutbound{Server: "192.0.2.10", ServerPort: 1080}
		resi := NewManager(cfg).StatusSnapshot()["resi"].(map[string]any)
		if resi["mux_limit"] != test.want {
			t.Fatalf("mux=%d cap=%v, want %d", test.mux, resi["mux_limit"], test.want)
		}
	}
}

func TestManagerNotReady(t *testing.T) {
	manager := NewManager(baseConfig(t))
	if manager.Ready() {
		t.Fatal("skeleton must not claim readiness without endpoints")
	}
}
