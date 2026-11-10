package singbox

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"testing"
)

var errTestResolve = errors.New("test resolver failure")

const tcpProfile = `client
dev tun
proto tcp-client
remote 203.0.113.1 443 tcp
resolv-retry infinite
nobind
persist-key
persist-tun
cipher AES-128-CBC
auth SHA1
auth-user-pass
<ca>
-----BEGIN CERTIFICATE-----
Q0E=
-----END CERTIFICATE-----
</ca>
<cert>
-----BEGIN CERTIFICATE-----
Q0VSVA==
-----END CERTIFICATE-----
</cert>
<key>
-----BEGIN PRIVATE KEY-----
S0VZ
-----END PRIVATE KEY-----
</key>
`

func minimalProfile(extra string) string {
	return "client\nproto tcp-client\nremote 203.0.113.1 443 tcp\n" + extra +
		"<ca>\nQ0E=\n</ca>\n"
}

func profileWithRemote(remote string) string {
	return "client\nproto tcp-client\nremote " + remote + "\n<ca>\nQ0E=\n</ca>\n"
}

func TestParseOVPNBasic(t *testing.T) {
	endpoint, err := ParseOVPN(tcpProfile, ParseOptions{Tag: "vpngate-0", OnDemand: true})
	if err != nil {
		t.Fatalf("ParseOVPN: %v", err)
	}
	if endpoint.Type != "openvpn-client" || endpoint.Tag != "vpngate-0" {
		t.Fatalf("type/tag = %q/%q", endpoint.Type, endpoint.Tag)
	}
	if endpoint.Server != "203.0.113.1" || endpoint.ServerPort != 443 {
		t.Fatalf("server = %q:%d", endpoint.Server, endpoint.ServerPort)
	}
	if endpoint.Network != "tcp" || endpoint.Username != "vpn" || endpoint.Password != "vpn" {
		t.Fatalf("network/credentials = %q/%q/%q", endpoint.Network, endpoint.Username, endpoint.Password)
	}
	if endpoint.Auth != "SHA1" || endpoint.AuthRetry != "nointeract" {
		t.Fatalf("auth = %q retry = %q", endpoint.Auth, endpoint.AuthRetry)
	}
	if endpoint.DataCiphersFallback != "AES-128-CBC" {
		t.Fatalf("fallback = %q", endpoint.DataCiphersFallback)
	}
	if len(endpoint.DataCiphers) != 3 || endpoint.DataCiphers[1] != "AES-256-CBC" || endpoint.DataCiphers[2] != "BF-CBC" {
		t.Fatalf("data ciphers = %#v", endpoint.DataCiphers)
	}
	if endpoint.OnDemand == nil || !*endpoint.OnDemand {
		t.Fatal("on_demand must be true")
	}
	if endpoint.PingInterval != "10s" || endpoint.PingRestart != "60s" {
		t.Fatalf("keepalive = %q/%q", endpoint.PingInterval, endpoint.PingRestart)
	}
	if endpoint.TLS.Certificate == "" || endpoint.TLS.ClientCertificate == "" || endpoint.TLS.ClientKey == "" {
		t.Fatal("tls blocks missing")
	}
	if endpoint.TLS.CertificateProfile != "legacy" {
		t.Fatalf("profile = %q", endpoint.TLS.CertificateProfile)
	}
	if endpoint.System || !endpoint.RedirectGateway {
		t.Fatalf("system/redirect = %v/%v", endpoint.System, endpoint.RedirectGateway)
	}
}

func TestParseOVPNKeepaliveVariants(t *testing.T) {
	cases := []struct {
		name     string
		extra    string
		interval string
		restart  string
		disabled *bool
		reneg    string
	}{
		{"keepalive", "keepalive 25 120\n", "25s", "120s", nil, ""},
		{"ping", "ping 30\nping-restart 300\n", "30s", "300s", nil, ""},
		{"defaults", "", "10s", "60s", nil, ""},
		{"reneg-off", "reneg-sec 0\n", "10s", "60s", Bool(true), ""},
		{"reneg-on", "reneg-sec 3600\n", "10s", "60s", nil, "3600s"},
		{"out-of-range", "keepalive 0 999999\n", "10s", "60s", nil, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			endpoint, err := ParseOVPN(minimalProfile(tc.extra), ParseOptions{OnDemand: true})
			if err != nil {
				t.Fatalf("ParseOVPN: %v", err)
			}
			if endpoint.PingInterval != tc.interval || endpoint.PingRestart != tc.restart {
				t.Fatalf("keepalive = %q/%q", endpoint.PingInterval, endpoint.PingRestart)
			}
			if (endpoint.RenegotiateDisabled == nil) != (tc.disabled == nil) {
				t.Fatalf("renegotiate_disabled = %v", endpoint.RenegotiateDisabled)
			}
			if endpoint.RenegotiateInterval != tc.reneg {
				t.Fatalf("renegotiate_interval = %q", endpoint.RenegotiateInterval)
			}
		})
	}
}

func TestParseOVPNTLSBlocks(t *testing.T) {
	t.Run("tls-auth direction", func(t *testing.T) {
		profile := minimalProfile("<tls-auth>\nVE9LRU4=\n</tls-auth>\nkey-direction 1\n")
		endpoint, err := ParseOVPN(profile, ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		wrap := endpoint.TLS.ControlWrap
		if wrap == nil || wrap.Type != "tls_auth" || wrap.Key != "VE9LRU4=" || wrap.Direction != "client" {
			t.Fatalf("control_wrap = %#v", wrap)
		}
	})
	t.Run("tls-auth server direction", func(t *testing.T) {
		profile := minimalProfile("<tls-auth>\nVE9LRU4=\n</tls-auth>\nkey-direction 0\n")
		endpoint, err := ParseOVPN(profile, ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.TLS.ControlWrap.Direction != "server" {
			t.Fatalf("direction = %q", endpoint.TLS.ControlWrap.Direction)
		}
	})
	t.Run("tls-crypt wins", func(t *testing.T) {
		profile := minimalProfile("<tls-auth>\nQQ==\n</tls-auth>\n<tls-crypt>\nQg==\n</tls-crypt>\nkey-direction 1\n")
		endpoint, err := ParseOVPN(profile, ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		wrap := endpoint.TLS.ControlWrap
		if wrap == nil || wrap.Type != "tls_crypt" || wrap.Key != "Qg==" || wrap.Direction != "" {
			t.Fatalf("control_wrap = %#v", wrap)
		}
	})
	t.Run("case insensitive block names", func(t *testing.T) {
		profile := "proto tcp-client\nremote 203.0.113.1 443 tcp\n<CA>\nQ0E=\n</CA>\n"
		endpoint, err := ParseOVPN(profile, ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.TLS.Certificate != "Q0E=" {
			t.Fatalf("certificate = %q", endpoint.TLS.Certificate)
		}
	})
}

func TestParseOVPNUppercasesCipher(t *testing.T) {
	endpoint, err := ParseOVPN(minimalProfile("cipher aes-256-gcm\n"), ParseOptions{OnDemand: true})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.DataCiphers[0] != "AES-256-GCM" || endpoint.DataCiphersFallback != "AES-256-GCM" {
		t.Fatalf("ciphers = %#v", endpoint.DataCiphers)
	}
}

func TestParseOVPNRemoteSelection(t *testing.T) {
	t.Run("multiple tcp remotes", func(t *testing.T) {
		profile := minimalProfile("remote 203.0.113.2 8443 tcp\nremote 203.0.113.3 443 tcp\n")
		endpoint, err := ParseOVPN(profile, ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.Server != "" || endpoint.ServerPort != 0 {
			t.Fatalf("singular fields must be empty: %q:%d", endpoint.Server, endpoint.ServerPort)
		}
		if len(endpoint.Servers) != 3 {
			t.Fatalf("servers = %#v", endpoint.Servers)
		}
		for _, item := range endpoint.Servers {
			if item.Network != "tcp" {
				t.Fatalf("server network = %q", item.Network)
			}
		}
	})
	t.Run("dedupe", func(t *testing.T) {
		profile := minimalProfile("remote 203.0.113.2 8443 tcp\nremote 203.0.113.2 8443 tcp\n")
		remotes, err := AllTCPRemotes(profile, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(remotes) != 2 {
			t.Fatalf("deduped remotes = %#v", remotes)
		}
	})
	t.Run("cap", func(t *testing.T) {
		var builder strings.Builder
		for index := 1; index <= 20; index++ {
			fmt.Fprintf(&builder, "remote 198.51.100.%d %d tcp\n", index, 4000+index)
		}
		profile := minimalProfile(builder.String())
		if _, err := AllTCPRemotes(profile, true); err == nil {
			t.Fatal("expected too-many-remotes error")
		}
	})
	t.Run("exactly the cap", func(t *testing.T) {
		var builder strings.Builder
		for index := 1; index <= MaxRemotes-1; index++ {
			fmt.Fprintf(&builder, "remote 198.51.100.%d %d tcp\n", index, 4000+index)
		}
		profile := minimalProfile(builder.String())
		remotes, err := AllTCPRemotes(profile, true)
		if err != nil {
			t.Fatal(err)
		}
		if len(remotes) != MaxRemotes {
			t.Fatalf("remotes = %d", len(remotes))
		}
	})
	t.Run("explicit tcp beats global udp", func(t *testing.T) {
		profile := "proto udp\nremote 203.0.113.9 1194 udp\nremote 203.0.113.1 443 tcp\n<ca>\nQ0E=\n</ca>\n"
		remotes, err := AllTCPRemotes(profile, false)
		if err != nil {
			t.Fatal(err)
		}
		if len(remotes) != 1 || remotes[0].Port != 443 {
			t.Fatalf("remotes = %#v", remotes)
		}
	})
	t.Run("udp only", func(t *testing.T) {
		profile := "proto udp\nremote 203.0.113.9 1194 udp\n<ca>\nQ0E=\n</ca>\n"
		if _, err := ParseOVPN(profile, ParseOptions{OnDemand: true}); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestParseOVPNRejectsUnsafeInput(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		opts    ParseOptions
	}{
		{"missing ca", "proto tcp-client\nremote 203.0.113.1 443 tcp\n", ParseOptions{}},
		{"unterminated ca", "proto tcp-client\nremote 203.0.113.1 443 tcp\n<ca>\nQ0E=\n", ParseOptions{}},
		{"cert without key", minimalProfile("<cert>\nQ0VSVA==\n</cert>\n"), ParseOptions{}},
		{"key without cert", minimalProfile("<key>\nS0VZ\n</key>\n"), ParseOptions{}},
		{"private remote", profileWithRemote("127.0.0.1 22 tcp"), ParseOptions{}},
		{"metadata remote", profileWithRemote("169.254.169.254 80 tcp"), ParseOptions{}},
		{"localhost name", profileWithRemote("localhost 22 tcp"), ParseOptions{}},
		{"port zero", profileWithRemote("203.0.113.4 0 tcp"), ParseOptions{}},
		{"port too high", profileWithRemote("203.0.113.4 70000 tcp"), ParseOptions{}},
		{"bad cipher", minimalProfile("cipher TEA-CBC\n"), ParseOptions{}},
		{"bad auth", minimalProfile("auth WHIRLPOOL\n"), ParseOptions{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseOVPN(tc.profile, tc.opts); err == nil {
				t.Fatal("expected error")
			}
		})
	}
	t.Run("private allowed", func(t *testing.T) {
		profile := "client\nproto tcp-client\nremote 127.0.0.1 22 tcp\n<ca>\nQ0E=\n</ca>\n"
		endpoint, err := ParseOVPN(profile,
			ParseOptions{OnDemand: true, AllowPrivateRemotes: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.Server != "127.0.0.1" || endpoint.ServerPort != 22 {
			t.Fatalf("server = %q:%d", endpoint.Server, endpoint.ServerPort)
		}
	})
	t.Run("private remote is skipped when a public one remains", func(t *testing.T) {
		endpoint, err := ParseOVPN(minimalProfile("remote 127.0.0.1 22 tcp\n"),
			ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.Server != "203.0.113.1" || endpoint.ServerPort != 443 {
			t.Fatalf("server = %q:%d", endpoint.Server, endpoint.ServerPort)
		}
	})
	t.Run("bad port is skipped when a public one remains", func(t *testing.T) {
		endpoint, err := ParseOVPN(minimalProfile("remote 203.0.113.4 70000 tcp\n"),
			ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.Server != "203.0.113.1" {
			t.Fatalf("server = %q", endpoint.Server)
		}
	})
	t.Run("unresolvable hostname skipped when resolver rejects", func(t *testing.T) {
		resolver := func(string) ([]net.IP, error) { return nil, errTestResolve }
		if _, err := ParseOVPN(profileWithRemote("a.example 443 tcp"), ParseOptions{
			OnDemand: true, ResolveHost: resolver,
		}); err == nil {
			t.Fatal("expected all-rejected error")
		}
		endpoint, err := ParseOVPN(minimalProfile("remote a.example 443 tcp\n"), ParseOptions{
			OnDemand: true, ResolveHost: resolver,
		})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.Server != "203.0.113.1" {
			t.Fatalf("server = %q", endpoint.Server)
		}
	})
	t.Run("resolved private host is rejected", func(t *testing.T) {
		resolver := func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.5")}, nil }
		if _, err := ParseOVPN(profileWithRemote("a.example 443 tcp"), ParseOptions{
			OnDemand: true, ResolveHost: resolver,
		}); err == nil {
			t.Fatal("expected all-rejected error")
		}
	})
}

func TestParseOVPNLimits(t *testing.T) {
	t.Run("config too large", func(t *testing.T) {
		profile := minimalProfile(strings.Repeat("#", MaxConfigBytes+1))
		if _, err := ParseOVPN(profile, ParseOptions{}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("line too large", func(t *testing.T) {
		profile := "proto tcp-client\nremote 203.0.113.1 443 tcp\n# " +
			strings.Repeat("A", MaxConfigLineBytes) + "\n"
		if _, err := ParseOVPN(profile, ParseOptions{}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("block too large", func(t *testing.T) {
		profile := "proto tcp-client\nremote 203.0.113.1 443 tcp\n<ca>\n" +
			strings.Repeat("A", MaxBlockBytes+1) + "\n</ca>\n"
		if _, err := ParseOVPN(profile, ParseOptions{}); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("literal less-than before block", func(t *testing.T) {
		profile := "proto tcp-client\nremote 203.0.113.1 443 tcp\n# a < b\n<ca>\nQ0E=\n</ca>\n"
		endpoint, err := ParseOVPN(profile, ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.TLS.Certificate != "Q0E=" {
			t.Fatalf("certificate = %q", endpoint.TLS.Certificate)
		}
	})
}

func TestParseOVPNInlineBlockRules(t *testing.T) {
	t.Run("comment mentioning a tag is ignored", func(t *testing.T) {
		profile := "proto tcp-client\nremote 203.0.113.1 443 tcp\n# <ca> not a block\n<ca>\nQ0E=\n</ca>\n"
		endpoint, err := ParseOVPN(profile, ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.TLS.Certificate != "Q0E=" {
			t.Fatalf("certificate = %q", endpoint.TLS.Certificate)
		}
	})
	t.Run("unicode before block does not shift content", func(t *testing.T) {
		profile := "proto tcp-client\nremote 203.0.113.1 443 tcp\n# İstanbul\n<ca>\nQ0E=\n</ca>\n"
		endpoint, err := ParseOVPN(profile, ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.TLS.Certificate != "Q0E=" {
			t.Fatalf("certificate = %q", endpoint.TLS.Certificate)
		}
	})
	t.Run("single-line block", func(t *testing.T) {
		profile := "proto tcp-client\nremote 203.0.113.1 443 tcp\n<ca>Q0E=</ca>\n"
		endpoint, err := ParseOVPN(profile, ParseOptions{OnDemand: true})
		if err != nil {
			t.Fatal(err)
		}
		if endpoint.TLS.Certificate != "Q0E=" {
			t.Fatalf("certificate = %q", endpoint.TLS.Certificate)
		}
	})
	t.Run("non-PEM body is rejected", func(t *testing.T) {
		profile := "proto tcp-client\nremote 203.0.113.1 443 tcp\n<ca>\n<script>x</script>\n</ca>\n"
		if _, err := ParseOVPN(profile, ParseOptions{OnDemand: true}); err == nil {
			t.Fatal("expected non-PEM block rejection")
		}
	})
	t.Run("unterminated block is rejected", func(t *testing.T) {
		profile := "proto tcp-client\nremote 203.0.113.1 443 tcp\n<ca>\nQ0E=\n"
		if _, err := ParseOVPN(profile, ParseOptions{OnDemand: true}); err == nil {
			t.Fatal("expected unterminated block rejection")
		}
	})
}

func TestParseOVPNRemotePinning(t *testing.T) {
	if _, err := ParseOVPN(profileWithRemote("a.example 443 tcp"), ParseOptions{OnDemand: true}); err == nil {
		t.Fatal("hostname without a resolver must be rejected")
	}
	resolver := func(string) ([]net.IP, error) { return []net.IP{net.ParseIP("203.0.113.5")}, nil }
	endpoint, err := ParseOVPN(profileWithRemote("a.example 443 tcp"), ParseOptions{
		OnDemand: true, ResolveHost: resolver,
	})
	if err != nil {
		t.Fatal(err)
	}
	if endpoint.Server != "203.0.113.5" {
		t.Fatalf("server = %q, want pinned IP", endpoint.Server)
	}
	for _, remote := range []string{"2002:a9fe:a9fe::1 443 tcp", "2001:0:1234::1 443 tcp"} {
		if _, err := ParseOVPN(profileWithRemote(remote), ParseOptions{OnDemand: true}); err == nil {
			t.Fatalf("expected %q to be rejected", remote)
		}
	}
}

func TestRemoteHelpers(t *testing.T) {
	endpoint := Endpoint{
		Server: "203.0.113.1", ServerPort: 443,
		Servers: []ServerAddr{{Server: "203.0.113.2", ServerPort: 8443, Network: "tcp"}},
	}
	host, port := PrimaryServer(endpoint)
	if host != "203.0.113.1" || port != 443 {
		t.Fatalf("primary = %q:%d", host, port)
	}
	remotes := EndpointRemotes(endpoint)
	if len(remotes) != 2 || remotes[1].Host != "203.0.113.2" {
		t.Fatalf("remotes = %#v", remotes)
	}
	multi := Endpoint{Servers: []ServerAddr{{Server: "203.0.113.3", ServerPort: 443}}}
	host, port = PrimaryServer(multi)
	if host != "203.0.113.3" || port != 443 {
		t.Fatalf("primary = %q:%d", host, port)
	}
	if remotes := EndpointRemotes(Endpoint{}); len(remotes) != 0 {
		t.Fatalf("empty remotes = %#v", remotes)
	}
}

func FuzzParseOVPN(f *testing.F) {
	f.Add(tcpProfile)
	f.Add(minimalProfile("<tls-auth>\nQQ==\n</tls-auth>\n"))
	f.Add("remote 127.0.0.1 22 tcp\n<ca>")
	f.Fuzz(func(t *testing.T, text string) {
		_, _ = ParseOVPN(text, ParseOptions{AllowPrivateRemotes: true})
	})
}

func FuzzParseRemotes(f *testing.F) {
	f.Add("remote 203.0.113.1 443 tcp\nproto tcp-client")
	f.Fuzz(func(t *testing.T, text string) {
		_, _ = AllTCPRemotes(text, true)
	})
}
