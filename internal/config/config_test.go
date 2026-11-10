package config

import "testing"

func TestFromGetterDefaults(t *testing.T) {
	cfg := FromGetter(func(string) string { return "" })
	if cfg.Listen != DefaultListen {
		t.Fatalf("Listen = %q, want %q", cfg.Listen, DefaultListen)
	}
	if cfg.ClashURL != DefaultClashURL {
		t.Fatalf("ClashURL = %q, want %q", cfg.ClashURL, DefaultClashURL)
	}
	if cfg.DefaultTimeoutMS != DefaultTimeoutMS {
		t.Fatalf("DefaultTimeoutMS = %d, want %d", cfg.DefaultTimeoutMS, DefaultTimeoutMS)
	}
	if cfg.Concurrency != DefaultConcurrency {
		t.Fatalf("Concurrency = %d, want %d", cfg.Concurrency, DefaultConcurrency)
	}
	if cfg.Token != "" || cfg.ClashSecret != "" {
		t.Fatalf("secrets should default to empty: %+v", cfg)
	}
}

func TestFromGetterOverrides(t *testing.T) {
	values := map[string]string{
		"PROBE_LISTEN":             "127.0.0.1:39999",
		"PROBE_TOKEN":              "token",
		"CLASH_URL":                "http://127.0.0.1:9091/",
		"CLASH_SECRET":             "secret",
		"PROBE_DEFAULT_TIMEOUT_MS": "1500",
		"PROBE_CONCURRENCY":        "3",
	}
	cfg := FromGetter(func(key string) string { return values[key] })
	if cfg.Listen != "127.0.0.1:39999" || cfg.Token != "token" {
		t.Fatalf("unexpected listen/token: %+v", cfg)
	}
	if cfg.ClashURL != "http://127.0.0.1:9091" {
		t.Fatalf("ClashURL = %q", cfg.ClashURL)
	}
	if cfg.ClashSecret != "secret" || cfg.DefaultTimeoutMS != 1500 || cfg.Concurrency != 3 {
		t.Fatalf("unexpected config: %+v", cfg)
	}
}

func TestFromGetterInvalidNumbersFallBack(t *testing.T) {
	values := map[string]string{
		"PROBE_DEFAULT_TIMEOUT_MS": "nope",
		"PROBE_CONCURRENCY":        "-4",
	}
	cfg := FromGetter(func(key string) string { return values[key] })
	if cfg.DefaultTimeoutMS != DefaultTimeoutMS || cfg.Concurrency != DefaultConcurrency {
		t.Fatalf("invalid numbers were not ignored: %+v", cfg)
	}
}

func TestFromGetterClampsConcurrency(t *testing.T) {
	cfg := FromGetter(func(key string) string {
		if key == "PROBE_CONCURRENCY" {
			return "1000000000"
		}
		return ""
	})
	if cfg.Concurrency != MaxConcurrency {
		t.Fatalf("Concurrency = %d, want %d", cfg.Concurrency, MaxConcurrency)
	}
}

func TestValidateLoopback(t *testing.T) {
	allowed := []string{"127.0.0.1:39001", "localhost:39001", "[::1]:39001", "127.0.0.2:1"}
	for _, listen := range allowed {
		if err := ValidateLoopback(listen); err != nil {
			t.Fatalf("ValidateLoopback(%q) = %v, want nil", listen, err)
		}
	}
	rejected := []string{"0.0.0.0:39001", ":39001", "example.com:39001", "192.0.2.1:39001", "not-an-address"}
	for _, listen := range rejected {
		if err := ValidateLoopback(listen); err == nil {
			t.Fatalf("ValidateLoopback(%q) = nil, want error", listen)
		}
	}
}
