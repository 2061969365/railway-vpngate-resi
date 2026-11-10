// Package config loads the vpngate-probe sidecar configuration from the
// process environment. It is intentionally small: the sidecar owns no files
// and exposes no other configuration surface.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
)

const (
	// DefaultListen keeps the sidecar on loopback. It is never meant to be
	// reachable through Railway or Cloudflare.
	DefaultListen = "127.0.0.1:39001"
	// DefaultClashURL matches the manager's sing-box Clash API.
	DefaultClashURL = "http://127.0.0.1:9090"
	// DefaultTimeoutMS is the per-request /v1/exit and /v1/delay budget.
	DefaultTimeoutMS = 8000
	// DefaultConcurrency bounds the fan-out of Clash delay probes.
	DefaultConcurrency = 8
	// MaxConcurrency is the hard cap for PROBE_CONCURRENCY. A typo such as
	// 1000000000 would otherwise make make(chan struct{}, n) allocate ~1GB.
	MaxConcurrency = 64
)

// Config is the complete sidecar configuration.
type Config struct {
	Listen           string
	Token            string
	ClashURL         string
	ClashSecret      string
	DefaultTimeoutMS int
	Concurrency      int
}

// FromEnv reads the configuration from the current environment.
func FromEnv() Config {
	return FromGetter(os.Getenv)
}

// FromGetter reads the configuration through getenv. Tests use it to avoid
// mutating the process environment.
func FromGetter(getenv func(string) string) Config {
	cfg := Config{
		Listen:      strings.TrimSpace(getenv("PROBE_LISTEN")),
		Token:       strings.TrimSpace(getenv("PROBE_TOKEN")),
		ClashURL:    strings.TrimSpace(getenv("CLASH_URL")),
		ClashSecret: strings.TrimSpace(getenv("CLASH_SECRET")),
	}
	if cfg.Listen == "" {
		cfg.Listen = DefaultListen
	}
	if cfg.ClashURL == "" {
		cfg.ClashURL = DefaultClashURL
	}
	cfg.ClashURL = strings.TrimRight(cfg.ClashURL, "/")

	cfg.DefaultTimeoutMS = positiveInt(getenv("PROBE_DEFAULT_TIMEOUT_MS"), DefaultTimeoutMS)
	cfg.Concurrency = clampInt(positiveInt(getenv("PROBE_CONCURRENCY"), DefaultConcurrency), 1, MaxConcurrency)
	return cfg
}

func clampInt(value, minimum, maximum int) int {
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

func positiveInt(raw string, fallback int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

// ValidateLoopback rejects listen addresses that would expose the sidecar
// beyond the loopback interface. localhost is accepted and resolves to
// loopback by definition; every other host must parse as a loopback IP.
func ValidateLoopback(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("PROBE_LISTEN %q: %w", listen, err)
	}
	if host == "" {
		return errors.New("PROBE_LISTEN must name a loopback host")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("PROBE_LISTEN %q is not a loopback address", listen)
	}
	return nil
}
