package main

import (
	"strings"
	"testing"
)

func envMap(values map[string]string) func(string) string {
	return func(name string) string { return values[name] }
}

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(envMap(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.PasswordGenerated || len(cfg.Password) < minProxyPassLen {
		t.Fatalf("password = %q generated=%v", cfg.Password, cfg.PasswordGenerated)
	}
	if !cfg.AdminTokenGenerated || len(cfg.AdminToken) < minAdminTokenLen || cfg.AdminToken == "vpn" {
		t.Fatalf("admin token = %q generated=%v", cfg.AdminToken, cfg.AdminTokenGenerated)
	}
	if cfg.Port != 3000 || cfg.MixedPort != 40000 || cfg.BindHost != "0.0.0.0" {
		t.Fatalf("ports = %d/%d bind=%q", cfg.Port, cfg.MixedPort, cfg.BindHost)
	}
	if cfg.RefreshSeconds != 3600 || cfg.Limit != 100 || cfg.RealTopK != 30 {
		t.Fatalf("defaults = %d/%d/%d", cfg.RefreshSeconds, cfg.Limit, cfg.RealTopK)
	}
	if !cfg.AutoRescue || !cfg.PersistPinned {
		t.Fatal("boolean defaults changed")
	}
	if cfg.Resi != nil || cfg.ResiRotate {
		t.Fatal("resi must be disabled without RESI_GATEWAY/VLESS_UUID")
	}
	if cfg.Username != "u" || cfg.CloudflaredBin != "cloudflared" {
		t.Fatalf("username/bin = %q/%q", cfg.Username, cfg.CloudflaredBin)
	}
	if cfg.SnapshotURL != defaultSnapshotURL || len(cfg.SnapshotURLs) != 1 {
		t.Fatalf("snapshot = %q %#v", cfg.SnapshotURL, cfg.SnapshotURLs)
	}
}

func TestLoadConfigAdminTokenPolicy(t *testing.T) {
	for _, token := range []string{"vpn", "short", strings.Repeat("x", 15)} {
		_, err := LoadConfig(envMap(map[string]string{"ADMIN_TOKEN": token}))
		if err == nil {
			t.Fatalf("token %q must be rejected", token)
		}
	}
	cfg, err := LoadConfig(envMap(map[string]string{
		"ADMIN_TOKEN": "0123456789abcdef",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AdminTokenGenerated || cfg.AdminToken != "0123456789abcdef" {
		t.Fatalf("token = %q generated=%v", cfg.AdminToken, cfg.AdminTokenGenerated)
	}
	cfg, err = LoadConfig(envMap(map[string]string{
		"ADMIN_TOKEN": "vpn", "ALLOW_INSECURE_ADMIN": "1",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.AdminTokenInsecure {
		t.Fatal("insecure override not recorded")
	}
}

func TestLoadConfigProxyPassPolicy(t *testing.T) {
	if _, err := LoadConfig(envMap(map[string]string{"PROXY_PASS": "short"})); err == nil {
		t.Fatal("short PROXY_PASS must be rejected")
	}
	cfg, err := LoadConfig(envMap(map[string]string{"PROXY_PASS": "0123456789abcdef"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PasswordGenerated || cfg.Password != "0123456789abcdef" {
		t.Fatalf("password = %q", cfg.Password)
	}
}

func TestLoadConfigNumericValidation(t *testing.T) {
	bad := []map[string]string{
		{"PORT": "0"},
		{"PORT": "70000"},
		{"PORT": "abc"},
		{"MIXED_PORT": "0"},
		{"REFRESH_SECONDS": "59"},
		{"LIMIT": "101"},
		{"PROBE_WORKERS": "31"},
		{"DIAL_TIMEOUT": "4"},
		{"CLASH_API_PORT": "70000"},
	}
	for _, values := range bad {
		if _, err := LoadConfig(envMap(values)); err == nil {
			t.Fatalf("expected error for %#v", values)
		}
	}
	cfg, err := LoadConfig(envMap(map[string]string{
		"CHAIN_SETTLE_GRACE":    "200",
		"FAST_DELAY_TIMEOUT_MS": "100",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ChainSettleGrace != 120 || cfg.FastDelayTimeoutMS != 500 {
		t.Fatalf("clamped = %d/%d", cfg.ChainSettleGrace, cfg.FastDelayTimeoutMS)
	}
}

func TestLoadConfigBindAndCollisions(t *testing.T) {
	cfg, err := LoadConfig(envMap(map[string]string{"ADMIN_PORT": "3001"}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BindHost != "127.0.0.1" || cfg.AdminPort != 3001 {
		t.Fatalf("bind = %q admin=%d", cfg.BindHost, cfg.AdminPort)
	}
	cfg, err = LoadConfig(envMap(map[string]string{
		"ADMIN_PORT": "3001", "ADMIN_BIND": "192.0.2.5",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BindHost != "192.0.2.5" {
		t.Fatalf("bind = %q", cfg.BindHost)
	}
	bad := []map[string]string{
		{"MIXED_PORT": "8080"},
		{"VLESS_DIRECT_PORT": "9000", "VLESS_CHAIN_PORT": "9000"},
		{"PORT": "40000"},
		{"RESI_GATEWAY": "192.0.2.1:1080", "RESI_USER": "u", "RESI_PASS": "p", "VLESS_UUID": "uuid", "RESI_PORT": "8080"},
	}
	for _, values := range bad {
		if _, err := LoadConfig(envMap(values)); err == nil {
			t.Fatalf("expected collision error for %#v", values)
		}
	}
}

func TestLoadConfigSnapshotURLs(t *testing.T) {
	if _, err := LoadConfig(envMap(map[string]string{"SNAPSHOT_URL": "http://example.com/"})); err == nil {
		t.Fatal("http snapshot url must be rejected")
	}
	cfg, err := LoadConfig(envMap(map[string]string{
		"SNAPSHOT_URLS": "https://a.example/, https://b.example/",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.SnapshotURLs) != 2 || cfg.SnapshotURLs[1] != "https://b.example/" {
		t.Fatalf("mirrors = %#v", cfg.SnapshotURLs)
	}
}

func TestLoadConfigResiGateway(t *testing.T) {
	values := map[string]string{
		"RESI_GATEWAY":        "192.0.2.10:1080",
		"RESI_USER":           "ru",
		"RESI_PASS":           "rp",
		"VLESS_UUID":          "uuid",
		"RESI_SESSION_TTL":    "300",
		"RESI_USER_TEMPLATE":  "{user}-{session}",
		"RESI_PROBE_INTERVAL": "600",
	}
	cfg, err := LoadConfig(envMap(values))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Resi == nil || cfg.Resi.Server != "192.0.2.10" || cfg.Resi.ServerPort != 1080 {
		t.Fatalf("resi = %#v", cfg.Resi)
	}
	if cfg.ResiRotate {
		t.Fatal("gateway mode must not rotate")
	}
	if cfg.ResiSessionTTL != 300 || cfg.ResiProbeInterval != 600 {
		t.Fatalf("resi ttl/probe = %d/%d", cfg.ResiSessionTTL, cfg.ResiProbeInterval)
	}
	if len(cfg.Warnings) != 0 {
		t.Fatalf("warnings = %#v", cfg.Warnings)
	}

	rotation := map[string]string{
		"RESI_GATEWAY": "192.0.2.10:1080",
		"RESI_USER":    "ru",
		"RESI_PASS":    "rp",
		"VLESS_UUID":   "uuid",
	}
	cfg, err = LoadConfig(envMap(rotation))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ResiTemplate != "{user}" || cfg.ResiSessionTTL != 0 {
		t.Fatalf("rotation defaults = %q/%d", cfg.ResiTemplate, cfg.ResiSessionTTL)
	}

	bad := []map[string]string{
		{"RESI_GATEWAY": "nope", "RESI_USER": "u", "RESI_PASS": "p", "VLESS_UUID": "uuid"},
		{"RESI_GATEWAY": "192.0.2.1:0", "RESI_USER": "u", "RESI_PASS": "p", "VLESS_UUID": "uuid"},
		{"RESI_GATEWAY": "192.0.2.1:1080", "RESI_PASS": "p", "VLESS_UUID": "uuid"},
		{"RESI_GATEWAY": "192.0.2.1:1080", "RESI_USER": "u", "RESI_PASS": "p"},
		{"RESI_GATEWAY": "192.0.2.1:1080", "RESI_USER": "u", "RESI_PASS": "p", "VLESS_UUID": "uuid",
			"RESI_SESSION_TTL": "300", "RESI_USER_TEMPLATE": "{user}-{session}-{zone}"},
	}
	for _, values := range bad {
		if _, err := LoadConfig(envMap(values)); err == nil {
			t.Fatalf("expected resi error for %#v", values)
		}
	}
	t.Setenv("UNUSED", "")
}

func TestLoadConfigResiRotate(t *testing.T) {
	cfg, err := LoadConfig(envMap(map[string]string{"VLESS_UUID": "uuid"}))
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.ResiRotate || cfg.Resi != nil {
		t.Fatalf("rotate = %v resi=%#v", cfg.ResiRotate, cfg.Resi)
	}
}

func lookupMap(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestLoadConfigLookupExplicitEmpty(t *testing.T) {
	if _, err := LoadConfigLookup(lookupMap(map[string]string{"PORT": ""})); err == nil {
		t.Fatal("explicit empty numeric env must fail like Python int('')")
	}
	if _, err := LoadConfigLookup(lookupMap(map[string]string{"SNAPSHOT_URL": ""})); err == nil {
		t.Fatal("explicit empty SNAPSHOT_URL must fail the https check")
	}
	cfg, err := LoadConfigLookup(lookupMap(map[string]string{
		"PROXY_USER":      "",
		"RESI_PATH":       "",
		"CLOUDFLARED_BIN": "",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Username != "" || cfg.ResiPath != "" || cfg.CloudflaredBin != "" {
		t.Fatalf("explicit empty values must stay empty: %+v", cfg)
	}
}

func TestLoadConfigLookupAutoRepinAndResiWarning(t *testing.T) {
	cfg, err := LoadConfigLookup(lookupMap(map[string]string{
		"AUTO_REPIN":   "0",
		"RESI_GATEWAY": "127.0.0.1:1080",
		"RESI_USER":    "u",
		"RESI_PASS":    "p",
		"VLESS_UUID":   "uuid",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AutoRepin {
		t.Fatal("AUTO_REPIN=0 was not honored")
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "RESI_GATEWAY") && strings.Contains(warning, "private/loopback") {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing private RESI_GATEWAY warning: %v", cfg.Warnings)
	}
}

func TestLoadConfigLookupResourcePorts(t *testing.T) {
	cfg, err := LoadConfigLookup(lookupMap(map[string]string{
		"RESI_IN_PORT":     "42001",
		"RESI_ROTATE_BASE": "43000",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ResiInPort != 42001 || cfg.ResiRotateBase != 43000 {
		t.Fatalf("resi ports = %d/%d", cfg.ResiInPort, cfg.ResiRotateBase)
	}
	fallback, err := LoadConfigLookup(lookupMap(map[string]string{
		"RESI_IN_PORT":     "0",
		"RESI_ROTATE_BASE": "not-a-port",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if fallback.ResiInPort != 40001 || fallback.ResiRotateBase != 41000 {
		t.Fatalf("fallback ports = %d/%d", fallback.ResiInPort, fallback.ResiRotateBase)
	}
}

func TestLoadConfigSessionWarning(t *testing.T) {
	cfg, err := LoadConfig(envMap(map[string]string{
		"RESI_GATEWAY":     "192.0.2.1:1080",
		"RESI_USER":        "u",
		"RESI_PASS":        "p",
		"VLESS_UUID":       "uuid",
		"RESI_SESSION_TTL": "300",
	}))
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, warning := range cfg.Warnings {
		if strings.Contains(warning, "{session}") {
			found = true
		}
	}
	if !found {
		t.Fatalf("warnings = %#v", cfg.Warnings)
	}
}
