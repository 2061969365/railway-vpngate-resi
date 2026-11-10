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

	// DefaultMaxTunnels bounds concurrent hijacked tunnels. It is deliberately
	// higher than the Python manager's MAX_MUX_CONNECTIONS=100 to leave room for
	// both VLESS paths plus residential traffic.
	DefaultMaxTunnels = 256
	MinMaxTunnels     = 1
	MaxMaxTunnels     = 4096

	// DefaultMaxConns bounds every accepted TCP connection, before HTTP
	// parsing; over-limit connections are accepted and closed immediately.
	DefaultMaxConns = 1024
	MinMaxConns     = 1
	MaxMaxConns     = 1 << 20

	DefaultReadHeaderTimeoutMS = 10000
	DefaultMaxHeaderBytes      = 16 << 10
	MinMaxHeaderBytes          = 4 << 10
	MaxMaxHeaderBytes          = 8 << 20
)

// Config is the complete vpngate-edge configuration.
type Config struct {
	Listen            string
	AdminURL          string
	NodeAddr          string
	ChainAddr         string
	MetricsListen     string
	VLESSUUID         string
	DirectPath        string
	ChainPath         string
	ResiPath          string
	IdleTimeout       time.Duration
	DialTimeout       time.Duration
	ReadHeaderTimeout time.Duration
	MaxTunnels        int
	MaxConns          int
	MaxHeaderBytes    int
	// AllowRemoteAdmin is the explicit EDGE_ADMIN_ALLOW_REMOTE=1 escape. The
	// default requires a loopback admin host because /ws-resi is an arbitrary
	// raw TCP gateway to whatever EDGE_ADMIN names.
	AllowRemoteAdmin bool
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
	cfg.ReadHeaderTimeout = positiveMilliseconds(getenv("EDGE_READ_HEADER_TIMEOUT_MS"), DefaultReadHeaderTimeoutMS)
	cfg.MaxTunnels = boundedInt(getenv("EDGE_MAX_TUNNELS"), DefaultMaxTunnels, MinMaxTunnels, MaxMaxTunnels)
	cfg.MaxConns = boundedInt(getenv("EDGE_MAX_CONNS"), DefaultMaxConns, MinMaxConns, MaxMaxConns)
	cfg.MaxHeaderBytes = boundedInt(getenv("EDGE_MAX_HEADER_BYTES"), DefaultMaxHeaderBytes, MinMaxHeaderBytes, MaxMaxHeaderBytes)
	cfg.AllowRemoteAdmin = envBool(getenv("EDGE_ADMIN_ALLOW_REMOTE"))
	return cfg
}

func envBool(raw string) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
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

func boundedInt(raw string, fallback, minimum, maximum int) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return fallback
	}
	if value < minimum {
		return minimum
	}
	if value > maximum {
		return maximum
	}
	return value
}

// ValidateConfig rejects configurations that would silently break routing,
// collapse the two listeners onto one address, or bind an ephemeral port the
// manager cannot find. It is called by New so every caller shares the rules.
func ValidateConfig(cfg Config) error {
	paths := []struct {
		name  string
		value string
	}{
		{"VLESS_DIRECT_PATH", cfg.DirectPath},
		{"VLESS_CHAIN_PATH", cfg.ChainPath},
		{"RESI_PATH", cfg.ResiPath},
	}
	seen := make(map[string]string, len(paths))
	for _, path := range paths {
		if err := validatePath(path.name, path.value); err != nil {
			return err
		}
		if other, ok := seen[path.value]; ok {
			return fmt.Errorf("%s and %s must differ (both %q)", other, path.name, path.value)
		}
		seen[path.value] = path.name
	}

	backends := []struct {
		name  string
		value string
	}{
		{"EDGE_NODE", cfg.NodeAddr},
		{"EDGE_CHAIN", cfg.ChainAddr},
	}
	for _, backend := range backends {
		host, port, err := net.SplitHostPort(backend.value)
		if err != nil {
			return fmt.Errorf("%s %q: %w", backend.name, backend.value, err)
		}
		if strings.TrimSpace(host) == "" {
			return fmt.Errorf("%s %q must name a host", backend.name, backend.value)
		}
		if err := validatePort(backend.name, port); err != nil {
			return err
		}
	}

	if err := validateListen("EDGE_LISTEN", cfg.Listen); err != nil {
		return err
	}
	if err := validateListen("EDGE_METRICS_LISTEN", cfg.MetricsListen); err != nil {
		return err
	}
	if err := ValidateMetricsListen(cfg.MetricsListen); err != nil {
		return err
	}
	if sameAddress(cfg.Listen, cfg.MetricsListen) {
		return fmt.Errorf("EDGE_LISTEN and EDGE_METRICS_LISTEN must differ (both %q)", cfg.Listen)
	}

	if cfg.MaxTunnels < MinMaxTunnels || cfg.MaxTunnels > MaxMaxTunnels {
		return fmt.Errorf("EDGE_MAX_TUNNELS must be %d..%d (got %d)", MinMaxTunnels, MaxMaxTunnels, cfg.MaxTunnels)
	}
	if cfg.MaxConns < MinMaxConns || cfg.MaxConns > MaxMaxConns {
		return fmt.Errorf("EDGE_MAX_CONNS must be %d..%d (got %d)", MinMaxConns, MaxMaxConns, cfg.MaxConns)
	}
	if cfg.ReadHeaderTimeout <= 0 {
		return errors.New("EDGE_READ_HEADER_TIMEOUT_MS must be positive")
	}
	if cfg.MaxHeaderBytes < MinMaxHeaderBytes || cfg.MaxHeaderBytes > MaxMaxHeaderBytes {
		return fmt.Errorf("EDGE_MAX_HEADER_BYTES must be %d..%d (got %d)", MinMaxHeaderBytes, MaxMaxHeaderBytes, cfg.MaxHeaderBytes)
	}
	return nil
}

func validatePath(name, value string) error {
	if value == "" {
		return fmt.Errorf("%s must not be empty", name)
	}
	if !strings.HasPrefix(value, "/") {
		return fmt.Errorf("%s %q must start with /", name, value)
	}
	if value == "/" {
		return fmt.Errorf("%s must not be /", name)
	}
	if strings.Contains(value, "..") {
		return fmt.Errorf("%s %q must not contain ..", name, value)
	}
	if strings.ContainsAny(value, " \t\r\n") {
		return fmt.Errorf("%s %q must not contain whitespace", name, value)
	}
	if strings.ContainsAny(value, "?#") {
		return fmt.Errorf("%s %q must not contain ? or #", name, value)
	}
	return nil
}

func validateListen(name, value string) error {
	_, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("%s %q: %w", name, value, err)
	}
	return validatePort(name, port)
}

func validatePort(name, port string) error {
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65535 {
		return fmt.Errorf("%s %q: port must be 1..65535", name, port)
	}
	return nil
}

func sameAddress(left, right string) bool {
	leftHost, leftPort, leftErr := net.SplitHostPort(left)
	rightHost, rightPort, rightErr := net.SplitHostPort(right)
	if leftErr != nil || rightErr != nil || leftPort != rightPort {
		return false
	}
	// A wildcard bind overlaps every host on the same port.
	if isWildcardHost(leftHost) || isWildcardHost(rightHost) {
		return true
	}
	return strings.EqualFold(leftHost, rightHost)
}

func isWildcardHost(host string) bool {
	if strings.TrimSpace(host) == "" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsUnspecified()
}

// ValidateAdminHost requires the raw-tunnel backend host to be loopback.
// EDGE_ADMIN_ALLOW_REMOTE=1 is the documented escape for an intentional
// remote admin proxy; without it a mis-set EDGE_ADMIN would turn the public
// edge into an arbitrary TCP gateway.
func ValidateAdminHost(host string) error {
	trimmed := strings.TrimSpace(host)
	if trimmed == "" {
		return errors.New("EDGE_ADMIN must name a loopback host")
	}
	if strings.EqualFold(trimmed, "localhost") {
		return nil
	}
	ip := net.ParseIP(trimmed)
	if ip == nil || !ip.IsLoopback() {
		return fmt.Errorf("EDGE_ADMIN host %q must be loopback (localhost, 127.0.0.0/8 or ::1); set EDGE_ADMIN_ALLOW_REMOTE=1 to override", trimmed)
	}
	return nil
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
