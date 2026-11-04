package probe

import (
	"net"
	"strings"
)

// Target is one exit-IP echo endpoint. Port is almost always 443; keeping it
// explicit makes the CONNECT authority unambiguous.
type Target struct {
	Host string
	Port int
	Path string
}

// DefaultTargets mirrors vpngate_to_singbox.EXIT_IP_TARGETS. They are tried in
// order inside one timeout budget: one unreachable service must not burn the
// caller's whole deadline.
var DefaultTargets = []Target{
	{Host: "api.ipify.org", Port: 443, Path: "/?format=text"},
	{Host: "icanhazip.com", Port: 443, Path: "/"},
	{Host: "ifconfig.me", Port: 443, Path: "/ip"},
	{Host: "ipinfo.io", Port: 443, Path: "/ip"},
	{Host: "cloudflare.com", Port: 443, Path: "/cdn-cgi/trace"},
}

// MaxExitBody caps every exit-IP response body.
const MaxExitBody = 64 << 10

// ParseExitIP pulls an IPv4 address out of a plain ("203.0.113.7") or keyed
// ("ip=203.0.113.7", as served by cloudflare.com/cdn-cgi/trace) body.
func ParseExitIP(body []byte) (string, bool) {
	text := strings.TrimSpace(string(body))
	if ip := net.ParseIP(text); ip != nil && ip.To4() != nil {
		return ip.String(), true
	}
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		value, ok := strings.CutPrefix(line, "ip=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if ip := net.ParseIP(value); ip != nil && ip.To4() != nil {
			return ip.String(), true
		}
	}
	return "", false
}
