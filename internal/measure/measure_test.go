package measure

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"io"
	"math/big"
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/probe"
	"github.com/2061969365/railway-vpngate-combined/probe/internal/singbox"
)

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certificate, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsed)
	return certificate, pool
}

func startTLSServer(t *testing.T, status int, body string) (int, *tls.Config) {
	t.Helper()
	certificate, pool := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
	go func() {
		for {
			conn, err := tlsListener.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				reader := bufio.NewReader(conn)
				for {
					line, err := reader.ReadString('\n')
					if err != nil || line == "\r\n" {
						break
					}
				}
				reason := "OK"
				if status == 204 {
					reason = "No Content"
				}
				response := "HTTP/1.1 " + strconv.Itoa(status) + " " + reason + "\r\n" +
					"Content-Length: " + strconv.Itoa(len(body)) + "\r\n" +
					"Connection: close\r\n\r\n" + body
				_, _ = io.WriteString(conn, response)
			}(conn)
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	return port, &tls.Config{RootCAs: pool, ServerName: "localhost", MinVersion: tls.VersionTLS12}
}

type fakeSocks struct {
	port      int
	mu        sync.Mutex
	requested []string
}

func startFakeSocks(t *testing.T) *fakeSocks {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	proxy := &fakeSocks{port: listener.Addr().(*net.TCPAddr).Port}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go proxy.handle(conn)
		}
	}()
	return proxy
}

func (p *fakeSocks) handle(conn net.Conn) {
	defer conn.Close()
	head := make([]byte, 2)
	if _, err := io.ReadFull(conn, head); err != nil {
		return
	}
	methods := make([]byte, int(head[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}
	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return
	}
	var host string
	switch request[3] {
	case 0x01:
		address := make([]byte, 4)
		if _, err := io.ReadFull(conn, address); err != nil {
			return
		}
		host = net.IP(address).String()
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return
		}
		address := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, address); err != nil {
			return
		}
		host = string(address)
	case 0x04:
		address := make([]byte, 16)
		if _, err := io.ReadFull(conn, address); err != nil {
			return
		}
		host = net.IP(address).String()
	default:
		return
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return
	}
	port := int(binary.BigEndian.Uint16(portBytes))
	p.mu.Lock()
	p.requested = append(p.requested, net.JoinHostPort(host, strconv.Itoa(port)))
	p.mu.Unlock()
	target, err := net.Dial("tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return
	}
	go func() { _, _ = io.Copy(target, conn) }()
	_, _ = io.Copy(conn, target)
}

func TestTCPLatency(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	ms := TCPLatency(context.Background(), "127.0.0.1", port, 2*time.Second)
	if ms <= 0 {
		t.Fatalf("latency = %d", ms)
	}
	_ = listener.Close()
	if ms := TCPLatency(context.Background(), "127.0.0.1", port, 300*time.Millisecond); ms != 0 {
		t.Fatalf("closed port latency = %d", ms)
	}
}

func TestSocks5GetTextAndLatency(t *testing.T) {
	port, tlsConfig := startTLSServer(t, 200, "203.0.113.7")
	proxy := startFakeSocks(t)
	result := Socks5GetText(context.Background(), Socks5Options{
		ProxyHost: "127.0.0.1", ProxyPort: proxy.port,
		TargetHost: "localhost", TargetPort: port, Path: "/",
		Timeout: 5 * time.Second, TLSConfig: tlsConfig,
	})
	if result == nil {
		t.Fatal("Socks5GetText returned nil")
	}
	if result.Code != 200 || string(result.Body) != "203.0.113.7" {
		t.Fatalf("result = %+v body=%q", result, result.Body)
	}
	if result.MS < 1 {
		t.Fatalf("ms = %d", result.MS)
	}

	noContentPort, noContentTLS := startTLSServer(t, 204, "")
	latency := Socks5GetLatency(context.Background(), Socks5Options{
		ProxyHost: "127.0.0.1", ProxyPort: proxy.port,
		TargetHost: "localhost", TargetPort: noContentPort, Path: "/generate_204",
		Timeout: 5 * time.Second, TLSConfig: noContentTLS,
	})
	if latency == nil || *latency < 1 {
		t.Fatalf("latency = %v", latency)
	}
}

func TestSocks5RejectsUntrustedTLS(t *testing.T) {
	port, _ := startTLSServer(t, 200, "body")
	proxy := startFakeSocks(t)
	result := Socks5GetText(context.Background(), Socks5Options{
		ProxyHost: "127.0.0.1", ProxyPort: proxy.port,
		TargetHost: "localhost", TargetPort: port, Path: "/",
		Timeout: 2 * time.Second,
	})
	if result != nil {
		t.Fatalf("untrusted certificate accepted: %+v", result)
	}
}

func TestSocks5HonorsDeadline(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Keep the connection open without answering the greeting.
			go func() { defer conn.Close(); time.Sleep(2 * time.Second) }()
		}
	}()
	start := time.Now()
	result := Socks5GetText(context.Background(), Socks5Options{
		ProxyHost: "127.0.0.1", ProxyPort: port,
		TargetHost: "localhost", TargetPort: 443, Path: "/",
		Timeout: 300 * time.Millisecond,
	})
	if result != nil {
		t.Fatalf("result = %+v", result)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("deadline not honored: %s", elapsed)
	}
}

func TestFetchExitIPWithLocalTarget(t *testing.T) {
	port, tlsConfig := startTLSServer(t, 200, "203.0.113.9")
	proxy := startFakeSocks(t)
	exitIP, ms := FetchExitIP(context.Background(), FetchExitIPOptions{
		ProxyHost: "127.0.0.1", ProxyPort: proxy.port,
		Timeout: 5 * time.Second, TLSConfig: tlsConfig,
		Targets:             []probe.Target{{Host: "localhost", Port: port, Path: "/ip"}},
		AllowPrivateTargets: true,
	})
	if exitIP != "203.0.113.9" || ms == nil || *ms < 1 {
		t.Fatalf("exit = %q ms=%v", exitIP, ms)
	}
}

func TestMeasureMixedExitIP(t *testing.T) {
	port, tlsConfig := startTLSServer(t, 200, "ip=198.51.100.7")
	proxyPort, proxy := startCONNECTProxy(t)
	exitIP, ms := MeasureMixedExitIP(context.Background(), MixedOptions{
		ProxyHost: "127.0.0.1", ProxyPort: proxyPort,
		Username: "u", Password: "p",
		Timeout: 5 * time.Second, TLSConfig: tlsConfig,
		Targets:             []probe.Target{{Host: "localhost", Port: port, Path: "/ip"}},
		AllowPrivateTargets: true,
	})
	if exitIP != "198.51.100.7" || ms == nil {
		t.Fatalf("exit = %q ms=%v", exitIP, ms)
	}
	if !strings.Contains(proxy.lastAuth(), "Basic ") {
		t.Fatalf("proxy auth = %q", proxy.lastAuth())
	}
}

type fakeConnectProxy struct {
	mu   sync.Mutex
	auth string
}

func startCONNECTProxy(t *testing.T) (int, *fakeConnectProxy) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	proxy := &fakeConnectProxy{}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go proxy.handle(conn)
		}
	}()
	return listener.Addr().(*net.TCPAddr).Port, proxy
}

func (p *fakeConnectProxy) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	requestLine, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	fields := strings.Fields(requestLine)
	if len(fields) < 2 || fields[0] != "CONNECT" {
		return
	}
	authority := fields[1]
	authHeader := ""
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if line == "\r\n" {
			break
		}
		if name, value, ok := strings.Cut(line, ":"); ok {
			if strings.EqualFold(strings.TrimSpace(name), "Proxy-Authorization") {
				authHeader = strings.TrimSpace(value)
			}
		}
	}
	p.mu.Lock()
	p.auth = authHeader
	p.mu.Unlock()
	target, err := net.Dial("tcp", authority)
	if err != nil {
		_, _ = io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer target.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n"); err != nil {
		return
	}
	go func() { _, _ = io.Copy(target, reader) }()
	_, _ = io.Copy(conn, target)
}

func (p *fakeConnectProxy) lastAuth() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.auth
}

func TestDialProbeConfig(t *testing.T) {
	endpoint := singbox.Endpoint{
		Type: "openvpn-client", Tag: "vpngate-0",
		Server: "198.51.100.1", ServerPort: 443, Network: "tcp",
		Username: "vpn", Password: "vpn", Auth: "SHA1", AuthRetry: "nointeract",
		PingInterval: "10s", PingRestart: "60s", System: false, RedirectGateway: true,
	}
	config, err := DialProbeConfig(endpoint, 40123)
	if err != nil {
		t.Fatal(err)
	}
	route := config["route"].(map[string]any)
	if route["final"] != "dial-probe" {
		t.Fatalf("final = %v", route["final"])
	}
	endpoints := config["endpoints"].([]singbox.Endpoint)
	if len(endpoints) != 1 {
		t.Fatalf("endpoints = %d", len(endpoints))
	}
	probeEndpoint := endpoints[0]
	if probeEndpoint.Tag != "dial-probe" || probeEndpoint.AuthRetry != "none" {
		t.Fatalf("probe endpoint = %#v", probeEndpoint)
	}
	if probeEndpoint.PingInterval != "" || probeEndpoint.PingRestart != "" {
		t.Fatalf("ping fields = %q/%q", probeEndpoint.PingInterval, probeEndpoint.PingRestart)
	}
	if probeEndpoint.PingRestartDisabled == nil || !*probeEndpoint.PingRestartDisabled {
		t.Fatal("ping_restart_disabled missing")
	}
}

func TestResiProbeConfigs(t *testing.T) {
	config := ResiProbeConfig(singbox.ResiOutbound{
		Server: "192.0.2.10", ServerPort: 1080, Username: "u", Password: "p",
	}, 40100)
	outbounds := config["outbounds"].([]any)
	if len(outbounds) != 2 {
		t.Fatalf("outbounds = %d", len(outbounds))
	}
	socks := outbounds[0].(map[string]any)
	if socks["type"] != "socks" || socks["network"] != "tcp" {
		t.Fatalf("socks = %#v", socks)
	}
	rotate := ResiRotateProbeConfig("uuid", 8084, "/ws-resi", 40101)
	inbounds := rotate["inbounds"].([]any)
	if inbounds[0].(map[string]any)["listen_port"] != 40101 {
		t.Fatalf("rotate inbound = %#v", inbounds[0])
	}
}

func TestFreePort(t *testing.T) {
	port, err := FreePort()
	if err != nil {
		t.Fatal(err)
	}
	if port < 1 || port > 65535 {
		t.Fatalf("port = %d", port)
	}
}

func TestGate(t *testing.T) {
	gate := NewGate(1)
	ctx := context.Background()
	if err := gate.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	if gate.TryAcquire(10 * time.Millisecond) {
		t.Fatal("second acquire must block")
	}
	gate.Release()
	if !gate.TryAcquire(10 * time.Millisecond) {
		t.Fatal("slot was not released")
	}
	gate.Release()
	full := NewGate(1)
	if err := full.Acquire(ctx); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := full.Acquire(cancelled); err == nil {
		t.Fatal("expected context error")
	}
	full.Release()
}

func TestSocks5RejectsOversizedResponseHeaders(t *testing.T) {
	certificate, pool := testCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}})
	go func() {
		conn, err := tlsListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, err := reader.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nX-Big: "+
			strings.Repeat("a", MaxResponseBody+1024)+"\r\n\r\n")
	}()
	proxy := startFakeSocks(t)
	start := time.Now()
	result := Socks5GetText(context.Background(), Socks5Options{
		ProxyHost: "127.0.0.1", ProxyPort: proxy.port,
		TargetHost: "127.0.0.1", TargetPort: listener.Addr().(*net.TCPAddr).Port,
		Timeout:   3 * time.Second,
		TLSConfig: &tls.Config{RootCAs: pool, ServerName: "localhost"},
	})
	if result != nil {
		t.Fatalf("oversized headers were accepted: %+v", result)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("header cap was not enforced early: %s", elapsed)
	}
}

func TestFetchExitIPRejectsPrivateTargets(t *testing.T) {
	proxy := startFakeSocks(t)
	exitIP, ms := FetchExitIP(context.Background(), FetchExitIPOptions{
		ProxyHost: "127.0.0.1", ProxyPort: proxy.port,
		Timeout: 500 * time.Millisecond,
		Targets: []probe.Target{{Host: "127.0.0.1", Port: 443, Path: "/"}},
	})
	if exitIP != "" || ms != nil {
		t.Fatalf("private target accepted: %q %v", exitIP, ms)
	}
	if len(proxy.requested) != 0 {
		t.Fatalf("private target was dialed: %v", proxy.requested)
	}
}

func TestMeasureMixedExitIPForcesCertificateVerification(t *testing.T) {
	port, _ := startTLSServer(t, 200, "ip=198.51.100.7")
	proxyPort, _ := startCONNECTProxy(t)
	exitIP, ms := MeasureMixedExitIP(context.Background(), MixedOptions{
		ProxyHost: "127.0.0.1", ProxyPort: proxyPort,
		Timeout: 2 * time.Second,
		// InsecureSkipVerify must be ignored by probe.Exiter.
		TLSConfig:           &tls.Config{InsecureSkipVerify: true},
		Targets:             []probe.Target{{Host: "localhost", Port: port, Path: "/ip"}},
		AllowPrivateTargets: true,
	})
	if exitIP != "" || ms != nil {
		t.Fatalf("unverified TLS was accepted: %q %v", exitIP, ms)
	}
}

func TestGateAcquireTimeout(t *testing.T) {
	gate := NewGate(1)
	gate.Timeout = 40 * time.Millisecond
	if err := gate.Acquire(context.Background()); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err := gate.Acquire(context.Background())
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("second Acquire must time out")
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("gate timeout was not enforced: %s", elapsed)
	}
	gate.Release()
}

func TestFreePortConcurrentIsUnique(t *testing.T) {
	const count = 16
	ports := make(chan int, count)
	var wait sync.WaitGroup
	for index := 0; index < count; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			port, err := FreePort()
			if err != nil {
				t.Errorf("FreePort: %v", err)
				return
			}
			ports <- port
		}()
	}
	wait.Wait()
	close(ports)
	seen := make(map[int]struct{}, count)
	for port := range ports {
		if _, duplicate := seen[port]; duplicate {
			t.Fatalf("FreePort returned %d twice", port)
		}
		seen[port] = struct{}{}
	}
}

func TestPinEndpointPinsResolvedRemotes(t *testing.T) {
	resolver := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.5")}, nil
	}
	endpoint := singbox.Endpoint{
		Type: "openvpn-client", Server: "exit.example", ServerPort: 443,
	}
	pinned, err := pinEndpoint(endpoint, false, resolver)
	if err != nil {
		t.Fatal(err)
	}
	if pinned.Server != "203.0.113.5" || pinned.ServerPort != 443 {
		t.Fatalf("pinned endpoint = %+v", pinned)
	}
	private := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("169.254.169.254")}, nil
	}
	if _, err := pinEndpoint(endpoint, false, private); err == nil {
		t.Fatal("metadata address must be rejected")
	}
}

func TestResiSampleDistinct(t *testing.T) {
	sample := newResiSample([]string{"1.1.1.1", "1.1.1.1", "2.2.2.2"}, []int64{10, 20, 30}, nil)
	if sample.Count != 3 || sample.Distinct != 2 || sample.FirstMS != 10 || sample.LastMS != 30 {
		t.Fatalf("sample = %#v", sample)
	}
}
