// Package edge implements the public data-plane front proxy for the combined
// VPNGate deployment. It owns the public listener: VLESS WebSocket paths are
// forwarded as raw TCP to the local sing-box inbounds, the residential path is
// forwarded raw to the admin process (which already counts it), and everything
// else is reverse-proxied to the admin process.
package edge

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultListen        = "0.0.0.0:3000"
	DefaultAdminURL      = "http://127.0.0.1:3001"
	DefaultNodeAddr      = "127.0.0.1:8080"
	DefaultChainAddr     = "127.0.0.1:8082"
	DefaultMetricsListen = "127.0.0.1:39002"
	DefaultDirectPath    = "/ws-node"
	DefaultChainPath     = "/ws-chain"
	DefaultResiPath      = "/ws-resi"
	DefaultIdleTimeoutMS = 120000
	DefaultDialTimeoutMS = 5000
)

// Config is the complete vpngate-edge configuration.
type Config struct {
	Listen        string
	AdminURL      string
	NodeAddr      string
	ChainAddr     string
	MetricsListen string
	VLESSUUID     string
	DirectPath    string
	ChainPath     string
	ResiPath      string
	IdleTimeout   time.Duration
	DialTimeout   time.Duration
}

// LoadConfig reads the configuration from the process environment.
func LoadConfig() Config {
	return ConfigFromGetter(os.Getenv)
}

// ConfigFromGetter reads the configuration through getenv so tests can avoid
// mutating the process environment.
func ConfigFromGetter(getenv func(string) string) Config {
	cfg := Config{
		Listen:        valueOr(getenv("EDGE_LISTEN"), DefaultListen),
		AdminURL:      valueOr(getenv("EDGE_ADMIN"), DefaultAdminURL),
		NodeAddr:      valueOr(getenv("EDGE_NODE"), DefaultNodeAddr),
		ChainAddr:     valueOr(getenv("EDGE_CHAIN"), DefaultChainAddr),
		MetricsListen: valueOr(getenv("EDGE_METRICS_LISTEN"), DefaultMetricsListen),
		VLESSUUID:     strings.TrimSpace(getenv("VLESS_UUID")),
		DirectPath:    valueOr(getenv("VLESS_DIRECT_PATH"), DefaultDirectPath),
		ChainPath:     valueOr(getenv("VLESS_CHAIN_PATH"), DefaultChainPath),
		ResiPath:      valueOr(getenv("RESI_PATH"), DefaultResiPath),
	}
	cfg.IdleTimeout = positiveMilliseconds(getenv("EDGE_IDLE_TIMEOUT_MS"), DefaultIdleTimeoutMS)
	cfg.DialTimeout = positiveMilliseconds(getenv("EDGE_DIAL_TIMEOUT_MS"), DefaultDialTimeoutMS)
	return cfg
}

func valueOr(raw, fallback string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return fallback
	}
	return value
}

func positiveMilliseconds(raw string, fallback int) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return time.Duration(fallback) * time.Millisecond
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		return time.Duration(fallback) * time.Millisecond
	}
	return time.Duration(value) * time.Millisecond
}

// ValidateMetricsListen rejects metrics addresses that are not loopback-only.
// The public EDGE_LISTEN is intentionally allowed to bind 0.0.0.0; the metrics
// listener is not.
func ValidateMetricsListen(listen string) error {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("EDGE_METRICS_LISTEN %q: %w", listen, err)
	}
	if host == "" {
		return errors.New("EDGE_METRICS_LISTEN must name a loopback host")
	}
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("EDGE_METRICS_LISTEN %q is not a loopback address", listen)
	}
	return nil
}
