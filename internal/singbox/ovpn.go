package singbox

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"unicode"
)

const (
	// MaxConfigBytes caps one OpenVPN profile read from a snapshot row.
	MaxConfigBytes = 256 << 10
	// MaxConfigLineBytes caps one physical line before block parsing.
	MaxConfigLineBytes = 4 << 10
	// MaxBlockBytes caps one inline <ca>/<cert>/<key>/<tls-auth>/<tls-crypt>.
	MaxBlockBytes = 128 << 10
	// MaxRemotes caps the deduplicated TCP remote list of one profile.
	MaxRemotes = 8

	DefaultUsername = "vpn"
	DefaultPassword = "vpn"
	DefaultAuth     = "SHA1"
)

// DefaultDataCiphers mirrors vpngate_to_singbox.DEFAULT_DATA_CIPHERS.
var DefaultDataCiphers = []string{"AES-128-CBC", "AES-256-CBC", "BF-CBC"}

var allowedCiphers = map[string]struct{}{
	"AES-128-CBC": {}, "AES-256-CBC": {}, "BF-CBC": {},
	"AES-128-GCM": {}, "AES-256-GCM": {}, "CHACHA20-POLY1305": {},
}

var allowedAuth = map[string]struct{}{
	"SHA1": {}, "SHA256": {}, "SHA512": {}, "MD5": {},
}

var blockedIPNets = mustCIDRs(
	"0.0.0.0/8",      // "this network"
	"10.0.0.0/8",     // RFC1918
	"100.64.0.0/10",  // CGNAT
	"127.0.0.0/8",    // loopback
	"169.254.0.0/16", // link-local / cloud metadata
	"172.16.0.0/12",  // RFC1918
	"192.0.0.0/24",   // IETF protocol assignments
	"192.168.0.0/16", // RFC1918
	"198.18.0.0/15",  // benchmarking
	"224.0.0.0/4",    // multicast
	"240.0.0.0/4",    // reserved
	"255.255.255.255/32",
	"::/128",
	"::1/128",
	"2001::/32", // Teredo
	"2002::/16", // 6to4 (can embed 169.254.169.254)
	"fc00::/7",  // unique local
	"fe80::/10", // link-local
	"ff00::/8",  // multicast
)

var blockedMetadataHosts = map[string]struct{}{
	"localhost":                {},
	"metadata.google.internal": {},
	"metadata.goog":            {},
	"instance-data":            {},
}

func mustCIDRs(values ...string) []*net.IPNet {
	out := make([]*net.IPNet, 0, len(values))
	for _, value := range values {
		_, network, err := net.ParseCIDR(value)
		if err != nil {
			panic(err)
		}
		out = append(out, network)
	}
	return out
}

// HostResolver resolves a hostname for private-address screening. The pure
// parser never resolves anything itself; the manager layer injects
// net.DefaultResolver.LookupIP in production.
type HostResolver func(host string) ([]net.IP, error)

// ParseOptions controls ParseOVPN. AllowPrivateRemotes maps to
// ALLOW_PRIVATE_REMOTES=1 (test fixtures use documentation addresses).
// Snapshot remotes are literal IPs by default (Python R2-2-02): a hostname is
// rejected unless ResolveHost is injected, and the resolved address is pinned
// into the endpoint so sing-box cannot re-resolve it at dial time.
type ParseOptions struct {
	Tag                 string
	Username            string
	Password            string
	OnDemand            bool
	AllowPrivateRemotes bool
	ResolveHost         HostResolver
}

// Remote is one (host, port) an endpoint may dial.
type Remote struct {
	Host string
	Port int
}

// ParseOVPN converts one OpenVPN client profile (TCP) to an endpoint.
//
// Inline blocks are scanned linearly: the old Python regex used DOTALL with a
// lazy quantifier, so an unterminated or repeated block could backtrack
// quadratically. This parser walks the text once, rejects oversized blocks and
// caps the remote list.
func ParseOVPN(text string, opts ParseOptions) (Endpoint, error) {
	username := opts.Username
	if username == "" {
		username = DefaultUsername
	}
	password := opts.Password
	if password == "" {
		password = DefaultPassword
	}
	if err := checkConfigSize(text); err != nil {
		return Endpoint{}, err
	}
	if strings.TrimSpace(text) == "" {
		return Endpoint{}, fmt.Errorf("empty openvpn config")
	}
	directives := scanDirectives(text)
	remotes, err := selectTCPRemotes(directives, opts.AllowPrivateRemotes, opts.ResolveHost)
	if err != nil {
		return Endpoint{}, err
	}
	blocks, err := parseBlocks(text)
	if err != nil {
		return Endpoint{}, err
	}
	if blocks["ca"] == "" {
		return Endpoint{}, fmt.Errorf("missing <ca> block")
	}

	auth := DefaultAuth
	if len(directives.auth) > 0 {
		auth = strings.ToUpper(directives.auth[0])
	}
	if _, ok := allowedAuth[auth]; !ok {
		return Endpoint{}, fmt.Errorf("unsupported auth %q", auth)
	}
	dataCiphers := append([]string(nil), DefaultDataCiphers...)
	if len(directives.cipher) > 0 {
		cipher := strings.ToUpper(directives.cipher[0])
		if _, ok := allowedCiphers[cipher]; !ok {
			return Endpoint{}, fmt.Errorf("unsupported cipher %q", cipher)
		}
		filtered := []string{cipher}
		for _, candidate := range DefaultDataCiphers {
			if !strings.EqualFold(candidate, cipher) {
				filtered = append(filtered, candidate)
			}
		}
		dataCiphers = filtered
	}

	if blocks["cert"] != "" && blocks["key"] == "" {
		return Endpoint{}, fmt.Errorf("client <cert> without <key> (must be both or neither)")
	}
	if blocks["key"] != "" && blocks["cert"] == "" {
		return Endpoint{}, fmt.Errorf("client <key> without <cert> (must be both or neither)")
	}

	tls := TLS{Certificate: blocks["ca"], CertificateProfile: "legacy"}
	if blocks["cert"] != "" {
		tls.ClientCertificate = blocks["cert"]
	}
	if blocks["key"] != "" {
		tls.ClientKey = blocks["key"]
	}
	if blocks["tls-crypt"] != "" {
		tls.ControlWrap = &ControlWrap{Type: "tls_crypt", Key: blocks["tls-crypt"]}
	} else if blocks["tls-auth"] != "" {
		wrap := &ControlWrap{Type: "tls_auth", Key: blocks["tls-auth"]}
		if len(directives.keyDirection) > 0 {
			switch directives.keyDirection[0] {
			case "0":
				wrap.Direction = "server"
			case "1":
				wrap.Direction = "client"
			}
		}
		tls.ControlWrap = wrap
	}

	pingInterval, pingRestart, renegotiateDisabled, renegotiateInterval := keepaliveFields(directives)
	endpoint := Endpoint{
		Type:                "openvpn-client",
		Tag:                 opts.Tag,
		Network:             "tcp",
		Username:            username,
		Password:            password,
		TLS:                 tls,
		DataCiphers:         dataCiphers,
		DataCiphersFallback: dataCiphers[0],
		Auth:                auth,
		AuthRetry:           "nointeract",
		OnDemand:            Bool(opts.OnDemand),
		PingInterval:        pingInterval,
		PingRestart:         pingRestart,
		RenegotiateDisabled: renegotiateDisabled,
		RenegotiateInterval: renegotiateInterval,
		System:              false,
		RedirectGateway:     true,
	}
	setServerFields(&endpoint, remotes)
	if directives.remoteRandom {
		endpoint.RemoteRandom = Bool(true)
	}
	return endpoint, nil
}

// AllTCPRemotes returns every deduplicated TCP remote in failover order.
// Hostnames are not resolved; use AllTCPRemotesResolved for the private-range
// screening the manager applies in production.
func AllTCPRemotes(text string, allowPrivate bool) ([]Remote, error) {
	return AllTCPRemotesResolved(text, allowPrivate, nil)
}

// AllTCPRemotesResolved is AllTCPRemotes with an injected hostname resolver.
func AllTCPRemotesResolved(text string, allowPrivate bool, resolve HostResolver) ([]Remote, error) {
	if err := checkConfigSize(text); err != nil {
		return nil, err
	}
	return selectTCPRemotes(scanDirectives(text), allowPrivate, resolve)
}

func checkConfigSize(text string) error {
	if len(text) > MaxConfigBytes {
		return fmt.Errorf("openvpn config exceeds %d bytes", MaxConfigBytes)
	}
	for _, line := range splitSnapshotLines(text) {
		if len(line) > MaxConfigLineBytes {
			return fmt.Errorf("openvpn config line exceeds %d bytes", MaxConfigLineBytes)
		}
	}
	return nil
}

// PrimaryServer returns the first address sing-box tries for an endpoint.
func PrimaryServer(endpoint Endpoint) (string, int) {
	if endpoint.Server != "" {
		return endpoint.Server, endpoint.ServerPort
	}
	if len(endpoint.Servers) > 0 {
		return endpoint.Servers[0].Server, endpoint.Servers[0].ServerPort
	}
	return "", 0
}

// EndpointRemotes lists every address an endpoint may dial, primary first.
func EndpointRemotes(endpoint Endpoint) []Remote {
	out := make([]Remote, 0, 1+len(endpoint.Servers))
	if endpoint.Server != "" {
		out = append(out, Remote{Host: endpoint.Server, Port: endpoint.ServerPort})
	}
	for _, item := range endpoint.Servers {
		if item.Server != "" {
			out = append(out, Remote{Host: item.Server, Port: item.ServerPort})
		}
	}
	return out
}

func setServerFields(endpoint *Endpoint, remotes []Remote) {
	if len(remotes) == 1 {
		endpoint.Server = remotes[0].Host
		endpoint.ServerPort = remotes[0].Port
		return
	}
	servers := make([]ServerAddr, 0, len(remotes))
	for _, remote := range remotes {
		servers = append(servers, ServerAddr{
			Server: remote.Host, ServerPort: remote.Port, Network: "tcp",
		})
	}
	endpoint.Servers = servers
}

type rawRemote struct {
	host    string
	port    int
	proto   string
	badPort bool
}

type directiveSet struct {
	protos       []string
	remotes      []rawRemote
	auth         []string
	cipher       []string
	keyDirection []string
	keepalive    []string
	ping         []string
	pingRestart  []string
	renegSec     []string
	remoteRandom bool
}

func scanDirectives(text string) directiveSet {
	var out directiveSet
	for _, line := range splitSnapshotLines(text) {
		fields := strings.Fields(strings.TrimSpace(line))
		if len(fields) == 0 {
			continue
		}
		switch strings.ToLower(fields[0]) {
		case "remote":
			if len(fields) != 3 && len(fields) != 4 {
				continue
			}
			port, ok := parsePort(fields[2])
			remote := rawRemote{host: fields[1], port: port, badPort: !ok}
			if len(fields) == 4 {
				remote.proto = fields[3]
			}
			out.remotes = append(out.remotes, remote)
		case "proto":
			if len(fields) == 2 {
				out.protos = append(out.protos, fields[1])
			}
		case "auth":
			if len(fields) == 2 && out.auth == nil {
				out.auth = []string{fields[1]}
			}
		case "cipher":
			if len(fields) == 2 && out.cipher == nil {
				out.cipher = []string{fields[1]}
			}
		case "key-direction":
			if len(fields) == 2 && out.keyDirection == nil {
				out.keyDirection = []string{fields[1]}
			}
		case "keepalive":
			if len(fields) == 3 && out.keepalive == nil {
				out.keepalive = fields
			}
		case "ping":
			if len(fields) == 2 && out.ping == nil {
				out.ping = fields
			}
		case "ping-restart":
			if len(fields) == 2 && out.pingRestart == nil {
				out.pingRestart = fields
			}
		case "reneg-sec":
			if len(fields) == 2 && out.renegSec == nil {
				out.renegSec = fields
			}
		case "remote-random":
			if len(fields) == 1 {
				out.remoteRandom = true
			}
		}
	}
	return out
}

func parsePort(text string) (int, bool) {
	if text == "" {
		return 0, false
	}
	for _, r := range text {
		if r < '0' || r > '9' {
			return 0, false
		}
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil || value < 1 || value > 65535 {
		return 0, false
	}
	return int(value), true
}

func isTCPProto(proto string) bool {
	return strings.HasPrefix(strings.ToLower(proto), "tcp")
}

func selectTCPRemotes(directives directiveSet, allowPrivate bool, resolve HostResolver) ([]Remote, error) {
	if len(directives.remotes) == 0 {
		return nil, fmt.Errorf("no remote directive found")
	}
	globalTCP := false
	for _, proto := range directives.protos {
		if isTCPProto(proto) {
			globalTCP = true
			break
		}
	}
	candidates := make([]rawRemote, 0, len(directives.remotes))
	seen := make(map[string]struct{}, len(directives.remotes))
	for _, remote := range directives.remotes {
		if remote.proto != "" && !isTCPProto(remote.proto) {
			continue
		}
		if remote.proto == "" && !globalTCP {
			continue
		}
		key := remote.host + "\x00" + strconv.Itoa(remote.port)
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		candidates = append(candidates, remote)
	}
	if len(candidates) == 0 {
		return nil, fmt.Errorf("no TCP remote found (only UDP available)")
	}
	if len(candidates) > MaxRemotes {
		return nil, fmt.Errorf("too many TCP remotes (%d > %d)", len(candidates), MaxRemotes)
	}
	remotes := make([]Remote, 0, len(candidates))
	for _, remote := range candidates {
		if remote.badPort {
			continue
		}
		pinned, err := validateRemoteHost(remote.host, allowPrivate, resolve)
		if err != nil {
			continue
		}
		remotes = append(remotes, Remote{Host: pinned, Port: remote.port})
	}
	if len(remotes) == 0 {
		return nil, fmt.Errorf("no usable TCP remote (all rejected)")
	}
	return remotes, nil
}

// ValidateRemote applies the snapshot remote policy and returns the literal IP
// that must be dialed. Literal IPs are returned unchanged; a hostname needs an
// injected resolver and is pinned to its first validated address, so callers
// can never validate one address and dial another.
func ValidateRemote(host string, port int, allowPrivate bool, resolve HostResolver) (Remote, error) {
	if port < 1 || port > 65535 {
		return Remote{}, fmt.Errorf("port %d outside 1..65535", port)
	}
	pinned, err := validateRemoteHost(host, allowPrivate, resolve)
	if err != nil {
		return Remote{}, err
	}
	return Remote{Host: pinned, Port: port}, nil
}

// LookupHost is the production hostname resolver used by the probe/measure
// packages. Snapshot parsing itself never performs DNS.
func LookupHost(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}

func validateRemoteHost(host string, allowPrivate bool, resolve HostResolver) (string, error) {
	trimmed := strings.Trim(strings.TrimSpace(host), "[]")
	if trimmed == "" {
		return "", fmt.Errorf("empty remote host")
	}
	if !allowPrivate {
		if _, blocked := blockedMetadataHosts[strings.ToLower(trimmed)]; blocked {
			return "", fmt.Errorf("remote host %q is loopback/metadata", host)
		}
	}
	if ip := net.ParseIP(trimmed); ip != nil {
		if !allowPrivate && isForbiddenIP(ip) {
			return "", fmt.Errorf("remote host %q is private/loopback/reserved", host)
		}
		return ip.String(), nil
	}
	if allowPrivate {
		// Test/operator escape: keep the hostname so local labs do not need a
		// resolver and cannot be redirected by a one-shot pin.
		return trimmed, nil
	}
	if resolve == nil {
		// Snapshot-controlled hostnames are rejected outright: resolving them
		// here would add unbounded DNS cost and a second lookup at connect time.
		return "", fmt.Errorf("remote host %q is not a literal IP", host)
	}
	addresses, err := resolve(trimmed)
	if err != nil || len(addresses) == 0 {
		return "", fmt.Errorf("cannot resolve remote host %q", host)
	}
	for _, address := range addresses {
		if !allowPrivate && isForbiddenIP(address) {
			return "", fmt.Errorf("remote host %q resolves to a forbidden address", host)
		}
	}
	return addresses[0].String(), nil
}

// IsForbiddenIP reports whether ip is inside the snapshot SSRF deny policy.
func IsForbiddenIP(ip net.IP) bool {
	return isForbiddenIP(ip)
}

func isForbiddenIP(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		ip = ip4
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, network := range blockedIPNets {
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// blockTags mirrors Python's _BLOCK_TAGS order.
var blockTags = []string{"ca", "cert", "key", "tls-auth", "tls-crypt"}

// parseBlocks ports _parse_inline_blocks line by line. Opening/closing tags
// must occupy a whole line (or share one line as <ca>body</ca>); a comment
// that merely mentions <ca> is ignored. Only per-line case folding is used, so
// a Unicode character outside the block can never shift slice offsets. Every
// non-empty body must pass the PEM character whitelist, matching Python.
func parseBlocks(text string) (map[string]string, error) {
	blocks := make(map[string]string, len(blockTags))
	current := ""
	var content []string
	blockBytes := 0
	for _, rawLine := range splitSnapshotLines(text) {
		stripped := strings.TrimSpace(rawLine)
		lowered := strings.ToLower(stripped)
		if current == "" {
			for _, tag := range blockTags {
				opener := "<" + tag + ">"
				closer := "</" + tag + ">"
				if lowered == opener {
					current = tag
					content = nil
					blockBytes = 0
					break
				}
				if strings.HasPrefix(lowered, opener) &&
					strings.HasSuffix(lowered, closer) &&
					len(stripped) >= len(opener)+len(closer) {
					inner := strings.TrimSpace(stripped[len(opener) : len(stripped)-len(closer)])
					if len(inner) > MaxBlockBytes {
						return nil, fmt.Errorf("<%s> block exceeds %d bytes", tag, MaxBlockBytes)
					}
					if inner != "" && !isPEMBody(inner) {
						return nil, fmt.Errorf("<%s> block contains non-PEM characters", tag)
					}
					blocks[tag] = inner
					break
				}
			}
			continue
		}
		if lowered == "</"+current+">" {
			body := strings.TrimSpace(strings.Join(content, "\n"))
			if len(body) > MaxBlockBytes {
				return nil, fmt.Errorf("<%s> block exceeds %d bytes", current, MaxBlockBytes)
			}
			if body != "" && !isPEMBody(body) {
				return nil, fmt.Errorf("<%s> block contains non-PEM characters", current)
			}
			blocks[current] = body
			current = ""
			content = nil
			blockBytes = 0
			continue
		}
		content = append(content, rawLine)
		blockBytes += len(rawLine) + 1
		if blockBytes > MaxBlockBytes {
			return nil, fmt.Errorf("<%s> block exceeds %d bytes", current, MaxBlockBytes)
		}
	}
	if current != "" {
		return nil, fmt.Errorf("unterminated <%s> block", current)
	}
	return blocks, nil
}

// isPEMBody is Python's _PEM_BODY_RE: [A-Za-z0-9+/=_\-.\s]+.
func isPEMBody(text string) bool {
	for _, r := range text {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case r == '+' || r == '/' || r == '=' || r == '_' || r == '-' || r == '.':
		case unicode.IsSpace(r):
		default:
			return false
		}
	}
	return true
}

func keepaliveFields(directives directiveSet) (string, string, *bool, string) {
	var pingInterval, pingRestart string
	var renegotiateDisabled *bool
	var renegotiateInterval string

	if len(directives.keepalive) == 3 {
		interval, intervalErr := strconv.Atoi(directives.keepalive[1])
		timeout, timeoutErr := strconv.Atoi(directives.keepalive[2])
		if intervalErr == nil && interval >= 1 && interval <= 3600 {
			pingInterval = strconv.Itoa(interval) + "s"
		}
		if timeoutErr == nil && timeout >= 1 && timeout <= 86400 {
			pingRestart = strconv.Itoa(timeout) + "s"
		}
	} else {
		if len(directives.ping) == 2 {
			if value, err := strconv.Atoi(directives.ping[1]); err == nil && value >= 1 && value <= 3600 {
				pingInterval = strconv.Itoa(value) + "s"
			}
		}
		if len(directives.pingRestart) == 2 {
			if value, err := strconv.Atoi(directives.pingRestart[1]); err == nil && value >= 1 && value <= 86400 {
				pingRestart = strconv.Itoa(value) + "s"
			}
		}
	}
	if len(directives.renegSec) == 2 {
		if value, err := strconv.Atoi(directives.renegSec[1]); err == nil {
			if value == 0 {
				renegotiateDisabled = Bool(true)
			} else if value >= 1 && value <= 30*86400 {
				renegotiateInterval = strconv.Itoa(value) + "s"
			}
		}
	}
	if pingInterval == "" {
		pingInterval = "10s"
	}
	if pingRestart == "" {
		pingRestart = "60s"
	}
	return pingInterval, pingRestart, renegotiateDisabled, renegotiateInterval
}
