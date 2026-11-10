package main

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/singbox"
)

const (
	defaultPort             = 3000
	defaultMixedPort        = 40000
	defaultSnapshotURL      = "https://www.vpngate.net/api/iphone/"
	minProxyPassLen         = 16
	minAdminTokenLen        = 16
	defaultFastHealth       = 5
	defaultDeepHealth       = 30
	defaultChainSettleGrace = 20
	defaultFastDelayTimeout = 2500
)

// Config is the manager skeleton configuration. It mirrors
// build_config_from_env, except the admin token rules follow FIX-PLAN P0-1:
// a missing token is generated, while an explicit "vpn"/short token is
// rejected unless ALLOW_INSECURE_ADMIN=1.
type Config struct {
	Port      int
	AdminPort int
	BindHost  string

	MixedPort      int
	EdgeMetricsURL string

	Username            string
	Password            string
	PasswordGenerated   bool
	AdminToken          string
	AdminTokenGenerated bool
	AdminTokenInsecure  bool

	SnapshotURL  string
	SnapshotURLs []string

	RefreshSeconds   int
	Limit            int
	RealTopK         int
	DialWorkers      int
	FullProbeWorkers int
	ProbeWorkers     int
	DialTimeout      int

	AutoRescue    bool
	AutoRepin     bool
	PersistPinned bool

	HealthCheckInterval int
	FastHealthInterval  int
	DeepHealthInterval  int
	ChainSettleGrace    int
	FastDelayTimeoutMS  int
	MaxMuxConnections   int
	ClashAPIPort        int

	DataDir string

	VLESSUUID       string
	VLESSDirectPort int
	VLESSChainPort  int

	Resi              *singbox.ResiOutbound
	ResiTemplate      string
	ResiSessionTTL    int
	ResiProbeInterval int
	ResiPort          int
	ResiRotate        bool
	ResiPath          string
	ResiInPort        int
	ResiRotateBase    int

	TunnelToken    string
	CloudflaredBin string
	DisguisePath   string

	Warnings []string
}

// LoadConfig parses the manager environment through a string getter. An empty
// value is indistinguishable from an unset variable here; LoadConfigLookup is
// the exact os.LookupEnv-compatible entry used by main.
func LoadConfig(getenv func(string) string) (Config, error) {
	if getenv == nil {
		getenv = func(string) string { return "" }
	}
	return loadConfig(func(name string) (string, bool) {
		value := getenv(name)
		return value, value != ""
	})
}

// LoadConfigLookup parses the environment while distinguishing unset from
// explicitly empty variables, matching Python's env.get(name, default) and
// int("") fail-closed behavior.
func LoadConfigLookup(lookup func(string) (string, bool)) (Config, error) {
	if lookup == nil {
		lookup = func(string) (string, bool) { return "", false }
	}
	return loadConfig(lookup)
}

func loadConfig(lookup func(string) (string, bool)) (Config, error) {
	value := func(name string) string {
		raw, _ := lookup(name)
		return strings.TrimSpace(raw)
	}
	present := func(name, fallback string) string {
		if raw, ok := lookup(name); ok {
			return raw
		}
		return fallback
	}

	var cfg Config
	var warnings []string

	password, _ := lookup("PROXY_PASS")
	if password == "" {
		generated, err := randomToken(24)
		if err != nil {
			return Config{}, err
		}
		password = generated
		cfg.PasswordGenerated = true
	} else if len(password) < minProxyPassLen {
		return Config{}, fmt.Errorf("refusing to start: PROXY_PASS must be at least %d chars", minProxyPassLen)
	}
	cfg.Password = password

	adminToken, _ := lookup("ADMIN_TOKEN")
	if adminToken == "" {
		generated, err := randomToken(24)
		if err != nil {
			return Config{}, err
		}
		adminToken = generated
		cfg.AdminTokenGenerated = true
	} else if adminToken == "vpn" || len(adminToken) < minAdminTokenLen {
		if envBoolLookup(lookup, "ALLOW_INSECURE_ADMIN", false) {
			cfg.AdminTokenInsecure = true
			warnings = append(warnings, "ADMIN_TOKEN is weak but ALLOW_INSECURE_ADMIN=1 allows it")
		} else {
			return Config{}, fmt.Errorf("refusing to start: ADMIN_TOKEN must be at least %d chars and not 'vpn' (set ALLOW_INSECURE_ADMIN=1 to override)", minAdminTokenLen)
		}
	}
	cfg.AdminToken = adminToken

	snapshotURL := present("SNAPSHOT_URL", defaultSnapshotURL)
	mirrors := make([]string, 0, 4)
	rawMirrors, _ := lookup("SNAPSHOT_URLS")
	for _, part := range strings.Split(rawMirrors, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			mirrors = append(mirrors, trimmed)
		}
	}
	if len(mirrors) == 0 {
		mirrors = []string{snapshotURL}
	}
	for _, candidate := range mirrors {
		parsed, err := url.Parse(candidate)
		if err != nil || parsed.Scheme != "https" {
			return Config{}, fmt.Errorf("refusing to start: snapshot url must be https: %s", candidate)
		}
	}
	cfg.SnapshotURL = snapshotURL
	cfg.SnapshotURLs = mirrors

	var err error
	if cfg.MixedPort, err = intEnvLookup(lookup, "MIXED_PORT", defaultMixedPort, 1, 65535); err != nil {
		return Config{}, err
	}
	if cfg.Port, err = intEnvLookup(lookup, "PORT", defaultPort, 1, 65535); err != nil {
		return Config{}, err
	}
	cfg.AdminPort = cfg.Port
	cfg.BindHost = "0.0.0.0"
	adminRaw := value("ADMIN_PORT")
	if adminRaw != "" {
		if cfg.AdminPort, err = intEnvLookup(lookup, "ADMIN_PORT", cfg.Port, 1, 65535); err != nil {
			return Config{}, err
		}
		cfg.BindHost = "127.0.0.1"
	}
	if bind := value("ADMIN_BIND"); bind != "" {
		cfg.BindHost = bind
	}
	cfg.EdgeMetricsURL = value("EDGE_METRICS_URL")

	if cfg.VLESSDirectPort, err = intEnvLookup(lookup, "VLESS_DIRECT_PORT", 8080, 1, 65535); err != nil {
		return Config{}, err
	}
	if cfg.VLESSChainPort, err = intEnvLookup(lookup, "VLESS_CHAIN_PORT", 8082, 1, 65535); err != nil {
		return Config{}, err
	}
	if cfg.ResiPort, err = intEnvLookup(lookup, "RESI_PORT", singbox.DefaultResiPort, 1, 65535); err != nil {
		return Config{}, err
	}
	cfg.VLESSUUID = present("VLESS_UUID", "")
	cfg.Resi, cfg.ResiTemplate, cfg.ResiSessionTTL, cfg.ResiProbeInterval, err = resiFromEnv(lookup, &warnings)
	if err != nil {
		return Config{}, err
	}
	cfg.ResiRotate = cfg.Resi == nil && cfg.VLESSUUID != ""
	cfg.ResiPath = present("RESI_PATH", singbox.DefaultResiPath)
	cfg.ResiInPort = envIntDefault(lookup, "RESI_IN_PORT", singbox.ResiInPort)
	cfg.ResiRotateBase = envIntDefault(lookup, "RESI_ROTATE_BASE", singbox.ResiRotateBase)

	if cfg.VLESSDirectPort == cfg.VLESSChainPort {
		return Config{}, fmt.Errorf("refusing to start: VLESS ports collide (%d)", cfg.VLESSDirectPort)
	}
	if cfg.Resi != nil && cfg.VLESSUUID == "" {
		return Config{}, fmt.Errorf("refusing to start: RESI_GATEWAY needs VLESS_UUID (the resi path is a VLESS+WS inbound)")
	}
	reserved := map[int]struct{}{
		8080: {}, 8081: {}, 8082: {}, 4096: {},
		cfg.MixedPort: {}, cfg.VLESSDirectPort: {}, cfg.VLESSChainPort: {},
	}
	if cfg.Resi != nil || cfg.ResiRotate {
		if _, collision := reserved[cfg.ResiPort]; collision {
			return Config{}, fmt.Errorf("refusing to start: RESI_PORT=%d collides", cfg.ResiPort)
		}
		reserved[cfg.ResiPort] = struct{}{}
	}
	if cfg.MixedPort == 8080 || cfg.MixedPort == 8081 || cfg.MixedPort == 8082 ||
		cfg.MixedPort == 4096 || cfg.MixedPort == cfg.VLESSDirectPort ||
		cfg.MixedPort == cfg.VLESSChainPort {
		return Config{}, fmt.Errorf("refusing to start: MIXED_PORT=%d collides", cfg.MixedPort)
	}
	if _, collision := reserved[cfg.AdminPort]; collision {
		name := "PORT"
		if adminRaw != "" {
			name = "ADMIN_PORT"
		}
		return Config{}, fmt.Errorf("refusing to start: %s=%d collides", name, cfg.AdminPort)
	}
	if adminRaw == "" && cfg.AdminPort != defaultPort {
		warnings = append(warnings, fmt.Sprintf("PORT=%d is not 3000", cfg.AdminPort))
	}

	cfg.Username = present("PROXY_USER", "u")
	if cfg.RefreshSeconds, err = intEnvLookup(lookup, "REFRESH_SECONDS", 3600, 60, 86400); err != nil {
		return Config{}, err
	}
	if cfg.Limit, err = intEnvLookup(lookup, "LIMIT", 100, 0, 100); err != nil {
		return Config{}, err
	}
	if cfg.RealTopK, err = intEnvLookup(lookup, "REAL_TOPK", 30, 0, 100); err != nil {
		return Config{}, err
	}
	if cfg.DialWorkers, err = intEnvLookup(lookup, "DIAL_WORKERS", 2, 1, 5); err != nil {
		return Config{}, err
	}
	if cfg.FullProbeWorkers, err = intEnvLookup(lookup, "FULL_PROBE_WORKERS", 3, 1, 5); err != nil {
		return Config{}, err
	}
	if cfg.ProbeWorkers, err = intEnvLookup(lookup, "PROBE_WORKERS", 15, 1, 30); err != nil {
		return Config{}, err
	}
	if cfg.DialTimeout, err = intEnvLookup(lookup, "DIAL_TIMEOUT", 15, 5, 60); err != nil {
		return Config{}, err
	}
	cfg.AutoRescue = envBoolLookup(lookup, "AUTO_RESCUE", true)
	cfg.AutoRepin = envBoolLookup(lookup, "AUTO_REPIN", true)
	cfg.PersistPinned = envBoolLookup(lookup, "OPENVPN_PERSIST_PINNED", true)
	if cfg.HealthCheckInterval, err = intEnvLookup(lookup, "HEALTH_CHECK_INTERVAL", 20, 5, 300); err != nil {
		return Config{}, err
	}
	if cfg.FastHealthInterval, err = intEnvLookup(lookup, "FAST_HEALTH_INTERVAL", defaultFastHealth, 1, 60); err != nil {
		return Config{}, err
	}
	if cfg.DeepHealthInterval, err = intEnvLookup(lookup, "DEEP_HEALTH_INTERVAL", defaultDeepHealth, 5, 300); err != nil {
		return Config{}, err
	}
	if cfg.ChainSettleGrace, err = clampedIntEnvLookup(lookup, "CHAIN_SETTLE_GRACE", defaultChainSettleGrace, 5, 120); err != nil {
		return Config{}, err
	}
	if cfg.FastDelayTimeoutMS, err = clampedIntEnvLookup(lookup, "FAST_DELAY_TIMEOUT_MS", defaultFastDelayTimeout, 500, 5000); err != nil {
		return Config{}, err
	}
	if cfg.MaxMuxConnections, err = intEnvLookup(lookup, "MAX_MUX_CONNECTIONS", 100, 1, 1000); err != nil {
		return Config{}, err
	}
	if cfg.ClashAPIPort, err = intEnvLookup(lookup, "CLASH_API_PORT", 9090, 0, 65535); err != nil {
		return Config{}, err
	}
	cfg.DataDir = value("DATA_DIR")
	if cfg.DataDir == "" {
		cfg.DataDir = value("RAILWAY_VOLUME_MOUNT_PATH")
	}
	if cfg.DataDir == "" {
		cfg.DataDir = "."
	}
	cfg.TunnelToken, _ = lookup("TUNNEL_TOKEN")
	cfg.CloudflaredBin = present("CLOUDFLARED_BIN", "cloudflared")
	cfg.DisguisePath, _ = lookup("DISGUISE_PATH")
	cfg.Warnings = warnings
	return cfg, nil
}

func resiFromEnv(lookup func(string) (string, bool), warnings *[]string) (*singbox.ResiOutbound, string, int, int, error) {
	gatewayRaw, _ := lookup("RESI_GATEWAY")
	gateway := strings.TrimSpace(gatewayRaw)
	if gateway == "" {
		return nil, "", 0, 0, nil
	}
	index := strings.LastIndex(gateway, ":")
	if index < 0 {
		return nil, "", 0, 0, fmt.Errorf("refusing to start: RESI_GATEWAY must be host:port, got %q", gateway)
	}
	host := strings.TrimSpace(gateway[:index])
	portText := strings.TrimSpace(gateway[index+1:])
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = host[1 : len(host)-1]
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 || host == "" {
		return nil, "", 0, 0, fmt.Errorf("refusing to start: RESI_GATEWAY must be host:port, got %q", gateway)
	}
	if ip := net.ParseIP(host); ip != nil && singbox.IsForbiddenIP(ip) {
		*warnings = append(*warnings, fmt.Sprintf(
			"RESI_GATEWAY %s:%d is a private/loopback address; serving and probing use the same operator policy",
			host, port))
	}
	userRaw, _ := lookup("RESI_USER")
	user := strings.TrimSpace(userRaw)
	password, _ := lookup("RESI_PASS")
	if user == "" || password == "" {
		return nil, "", 0, 0, fmt.Errorf("refusing to start: RESI_GATEWAY needs RESI_USER and RESI_PASS")
	}
	ttl, err := intEnvLookup(lookup, "RESI_SESSION_TTL", 0, 0, 86400)
	if err != nil {
		return nil, "", 0, 0, err
	}
	template := "{user}"
	if raw, ok := lookup("RESI_USER_TEMPLATE"); ok {
		template = raw
	}
	if ttl > 0 && !strings.Contains(template, "{session}") {
		*warnings = append(*warnings, "RESI_SESSION_TTL>0 but RESI_USER_TEMPLATE has no {session}; staying in rotation mode")
	}
	if _, err := singbox.RenderResiUsername(user, template, ttl, "probe"); err != nil {
		return nil, "", 0, 0, fmt.Errorf("refusing to start: %w", err)
	}
	probeInterval, err := intEnvLookup(lookup, "RESI_PROBE_INTERVAL", 300, 60, 86400)
	if err != nil {
		return nil, "", 0, 0, err
	}
	return &singbox.ResiOutbound{
		Server: host, ServerPort: port, Username: user, Password: password,
	}, template, ttl, probeInterval, nil
}

func intEnvLookup(lookup func(string) (string, bool), name string, defaultValue, minimum, maximum int) (int, error) {
	raw, ok := lookup(name)
	if !ok {
		return defaultValue, nil
	}
	text := strings.TrimSpace(raw)
	if text == "" {
		// Python int("") is an error; explicit empty must not silently fall
		// back to a default that the operator thought they overrode.
		return 0, fmt.Errorf("refusing to start: %s must be an integer, got %q", name, raw)
	}
	value, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("refusing to start: %s must be an integer, got %q", name, raw)
	}
	if value < minimum {
		return 0, fmt.Errorf("refusing to start: %s=%d below minimum %d", name, value, minimum)
	}
	if value > maximum {
		return 0, fmt.Errorf("refusing to start: %s=%d above maximum %d", name, value, maximum)
	}
	return value, nil
}

func clampedIntEnvLookup(lookup func(string) (string, bool), name string, defaultValue, minimum, maximum int) (int, error) {
	raw, ok := lookup(name)
	if !ok {
		return defaultValue, nil
	}
	text := strings.TrimSpace(raw)
	if text == "" {
		return 0, fmt.Errorf("refusing to start: %s must be an integer, got %q", name, raw)
	}
	value, err := strconv.Atoi(text)
	if err != nil {
		return 0, fmt.Errorf("refusing to start: %s must be an integer, got %q", name, raw)
	}
	if value < minimum {
		value = minimum
	}
	if value > maximum {
		value = maximum
	}
	return value, nil
}

// envIntDefault mirrors Python's module-level _env_int (RESI_IN_PORT,
// RESI_ROTATE_BASE): garbage or out-of-range values fall back to the default.
func envIntDefault(lookup func(string) (string, bool), name string, defaultValue int) int {
	raw, ok := lookup(name)
	if !ok {
		return defaultValue
	}
	value, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil || value < 1 || value > 65535 {
		return defaultValue
	}
	return value
}

func envBoolLookup(lookup func(string) (string, bool), name string, defaultValue bool) bool {
	raw, ok := lookup(name)
	if !ok {
		return defaultValue
	}
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on":
		return true
	case "0", "false", "no", "off":
		return false
	default:
		return defaultValue
	}
}

func randomToken(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}
