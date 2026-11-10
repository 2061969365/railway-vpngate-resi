package probe

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeProxy struct {
	listener net.Listener
	backend  string
	status   string

	mu          sync.Mutex
	connects    []string
	authHeaders []string
}

func newFakeProxy(t *testing.T, backend string) *fakeProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen fake proxy: %v", err)
	}
	proxy := &fakeProxy{listener: listener, backend: backend}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go proxy.handle(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return proxy
}

func (p *fakeProxy) addr() (string, int) {
	host, port, err := net.SplitHostPort(p.listener.Addr().String())
	if err != nil {
		panic(err)
	}
	parsedPort := 0
	_, _ = fmt.Sscanf(port, "%d", &parsedPort)
	return host, parsedPort
}

func (p *fakeProxy) setStatus(status string) {
	p.mu.Lock()
	p.status = status
	p.mu.Unlock()
}

func (p *fakeProxy) handle(conn net.Conn) {
	defer conn.Close()
	reader := bufio.NewReader(conn)
	line, err := reader.ReadString('\n')
	if err != nil {
		return
	}
	p.mu.Lock()
	p.connects = append(p.connects, strings.TrimSpace(line))
	p.mu.Unlock()
	for {
		header, err := reader.ReadString('\n')
		if err != nil {
			return
		}
		if header == "\r\n" || header == "\n" {
			break
		}
		if value, ok := strings.CutPrefix(strings.ToLower(header), "proxy-authorization:"); ok {
			p.mu.Lock()
			p.authHeaders = append(p.authHeaders, strings.TrimSpace(value))
			p.mu.Unlock()
		}
	}
	p.mu.Lock()
	status := p.status
	p.mu.Unlock()
	if status == "" {
		status = "200 Connection Established"
	}
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 %s\r\n\r\n", status); err != nil {
		return
	}
	if !strings.HasPrefix(status, "200") {
		return
	}
	upstream, err := net.Dial("tcp", p.backend)
	if err != nil {
		return
	}
	defer upstream.Close()
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, &proxyReader{reader: reader, conn: conn})
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(conn, upstream)
	<-done
}

type proxyReader struct {
	reader *bufio.Reader
	conn   net.Conn
}

func (r *proxyReader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}

type sniRecorder struct {
	mu    sync.Mutex
	names []string
}

func (r *sniRecorder) record(name string) {
	r.mu.Lock()
	r.names = append(r.names, name)
	r.mu.Unlock()
}

func (r *sniRecorder) contains(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, got := range r.names {
		if got == name {
			return true
		}
	}
	return false
}

func newExitBackend(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *sniRecorder, *tls.Config) {
	t.Helper()
	recorder := &sniRecorder{}
	names := []string{
		"first.example", "second.example", "only.example", "slow.example",
		"big.example", "small.example", "hang.example", "ok.example", "x.example",
	}
	certificate, pool := testServerCertificate(t, names...)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			recorder.record(hello.ServerName)
			return nil, nil
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, recorder, &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
}

func testServerCertificate(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: names[0]},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:              names,
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
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
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

func TestParseExitIP(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
		ok   bool
	}{
		{name: "plain", body: "203.0.113.7\n", want: "203.0.113.7", ok: true},
		{name: "trace", body: "fl=abc\nh=cloudflare.com\nip=198.51.100.9\nts=1\n", want: "198.51.100.9", ok: true},
		{name: "crlf", body: "ip=192.0.2.4\r\n", want: "192.0.2.4", ok: true},
		{name: "empty", body: "", ok: false},
		{name: "not-ip", body: "hello", ok: false},
		{name: "ipv6", body: "2001:db8::1", ok: false},
		{name: "bad-trace", body: "ip=nope", ok: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := ParseExitIP([]byte(test.body))
			if ok != test.ok || got != test.want {
				t.Fatalf("ParseExitIP(%q) = (%q, %v), want (%q, %v)", test.body, got, ok, test.want, test.ok)
			}
		})
	}
}

func TestExitIPFallbackAndAuth(t *testing.T) {
	backend, sni, tlsConfig := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/first":
			http.Error(w, "nope", http.StatusInternalServerError)
		case "/second":
			_, _ = io.WriteString(w, "203.0.113.7\n")
		default:
			http.NotFound(w, r)
		}
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()

	exiter := &Exiter{
		Targets: []Target{
			{Host: "first.example", Port: 443, Path: "/first"},
			{Host: "second.example", Port: 443, Path: "/second"},
		},
		TLSConfig:           tlsConfig,
		AllowPrivateTargets: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := exiter.ExitIP(ctx, host, port, "user", "pass")
	if err != nil {
		t.Fatalf("ExitIP: %v", err)
	}
	if result.ExitIP != "203.0.113.7" || result.Target != "second.example" || result.MS < 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	if !sni.contains("second.example") {
		t.Fatalf("SNI did not carry the target host: %+v", sni.names)
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	wantConnect := []string{
		"CONNECT first.example:443 HTTP/1.1",
		"CONNECT second.example:443 HTTP/1.1",
	}
	if len(proxy.connects) != len(wantConnect) {
		t.Fatalf("connects = %v, want %v", proxy.connects, wantConnect)
	}
	for index := range wantConnect {
		if proxy.connects[index] != wantConnect[index] {
			t.Fatalf("connects = %v, want %v", proxy.connects, wantConnect)
		}
	}
	wantAuth := "basic " + strings.ToLower(base64.StdEncoding.EncodeToString([]byte("user:pass")))
	if len(proxy.authHeaders) != len(wantConnect) {
		t.Fatalf("auth headers = %v", proxy.authHeaders)
	}
	for _, got := range proxy.authHeaders {
		if got != wantAuth {
			t.Fatalf("auth header = %q, want %q", got, wantAuth)
		}
	}
}

func TestExitIPWithoutCredentialsSendsNoAuth(t *testing.T) {
	backend, _, tlsConfig := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "198.51.100.7")
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()

	exiter := &Exiter{
		Targets:             []Target{{Host: "only.example", Port: 443, Path: "/"}},
		TLSConfig:           tlsConfig,
		AllowPrivateTargets: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := exiter.ExitIP(ctx, host, port, "", ""); err != nil {
		t.Fatalf("ExitIP: %v", err)
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if len(proxy.authHeaders) != 0 {
		t.Fatalf("unexpected auth headers: %v", proxy.authHeaders)
	}
}

func TestExitIPTimeout(t *testing.T) {
	backend, _, tlsConfig := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()

	exiter := &Exiter{
		Targets:             []Target{{Host: "slow.example", Port: 443, Path: "/"}},
		TLSConfig:           tlsConfig,
		AllowPrivateTargets: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := exiter.ExitIP(ctx, host, port, "u", "p")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("ExitIP succeeded despite a hanging target")
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("timeout budget was not enforced: %v", elapsed)
	}
}

func TestExitIPRejectsOversizedBodyAndFallsBack(t *testing.T) {
	backend, _, tlsConfig := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/big":
			_, _ = io.WriteString(w, strings.Repeat("a", MaxExitBody+1))
		case "/small":
			_, _ = io.WriteString(w, "192.0.2.10")
		}
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()

	exiter := &Exiter{
		Targets: []Target{
			{Host: "big.example", Port: 443, Path: "/big"},
			{Host: "small.example", Port: 443, Path: "/small"},
		},
		TLSConfig:           tlsConfig,
		AllowPrivateTargets: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := exiter.ExitIP(ctx, host, port, "", "")
	if err != nil {
		t.Fatalf("ExitIP: %v", err)
	}
	if result.ExitIP != "192.0.2.10" || result.Target != "small.example" {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestExitIPConnectRejected(t *testing.T) {
	backend, _, tlsConfig := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "192.0.2.1")
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	proxy.setStatus("407 Proxy Authentication Required")
	host, port := proxy.addr()

	exiter := &Exiter{
		Targets:             []Target{{Host: "only.example", Port: 443, Path: "/"}},
		TLSConfig:           tlsConfig,
		AllowPrivateTargets: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exiter.ExitIP(ctx, host, port, "u", "p"); err == nil {
		t.Fatal("ExitIP accepted a rejected CONNECT")
	}
}

func TestExitIPPerTargetBudgetKeepsFallbacks(t *testing.T) {
	backend, _, tlsConfig := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/hang":
			select {
			case <-r.Context().Done():
			case <-time.After(10 * time.Second):
			}
		case "/ok":
			_, _ = io.WriteString(w, "203.0.113.11")
		default:
			http.NotFound(w, r)
		}
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()

	exiter := &Exiter{
		Targets: []Target{
			{Host: "hang.example", Port: 443, Path: "/hang"},
			{Host: "ok.example", Port: 443, Path: "/ok"},
		},
		TLSConfig:           tlsConfig,
		AllowPrivateTargets: true,
		TargetBudget:        150 * time.Millisecond,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	result, err := exiter.ExitIP(ctx, host, port, "", "")
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("ExitIP: %v after %s", err, elapsed)
	}
	if result.ExitIP != "203.0.113.11" || result.Target != "ok.example" {
		t.Fatalf("result = %+v, want the second target", result)
	}
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("per-target budget did not free the fallback: %s", elapsed)
	}
}

func TestExitIPRejectsOversizedResponseHeaders(t *testing.T) {
	backend, _, tlsConfig := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Big", strings.Repeat("a", MaxExitBody+1024))
		_, _ = io.WriteString(w, "203.0.113.7")
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()
	exiter := &Exiter{
		Targets:             []Target{{Host: "big.example", Port: 443, Path: "/"}},
		TLSConfig:           tlsConfig,
		AllowPrivateTargets: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := exiter.ExitIP(ctx, host, port, "", ""); err == nil {
		t.Fatal("oversized response headers were accepted")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("header cap was not enforced early: %s", elapsed)
	}
}

func TestExitIPPinsResolvedTargetButKeepsSNI(t *testing.T) {
	backend, sni, tlsConfig := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.7")
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()
	resolver := func(string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("203.0.113.55")}, nil
	}
	exiter := &Exiter{
		Targets:     []Target{{Host: "second.example", Port: 443, Path: "/"}},
		TLSConfig:   tlsConfig,
		ResolveHost: resolver,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := exiter.ExitIP(ctx, host, port, "", "")
	if err != nil {
		t.Fatalf("ExitIP: %v", err)
	}
	if result.ExitIP != "203.0.113.7" {
		t.Fatalf("result = %+v", result)
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	if len(proxy.connects) != 1 || proxy.connects[0] != "CONNECT 203.0.113.55:443 HTTP/1.1" {
		t.Fatalf("CONNECT did not use the pinned IP: %v", proxy.connects)
	}
	if !sni.contains("second.example") {
		t.Fatalf("SNI did not keep the original host: %v", sni.names)
	}
}

func TestExitIPForcesCertificateVerification(t *testing.T) {
	backend, _, _ := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.7")
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()
	exiter := &Exiter{
		Targets:             []Target{{Host: "second.example", Port: 443, Path: "/"}},
		TLSConfig:           &tls.Config{InsecureSkipVerify: true},
		AllowPrivateTargets: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exiter.ExitIP(ctx, host, port, "", ""); err == nil {
		t.Fatal("InsecureSkipVerify was honored instead of being forced off")
	}
}

func TestExitIPRejectsOversizedConnectLine(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		reader := bufio.NewReader(conn)
		for {
			line, readErr := reader.ReadString('\n')
			if readErr != nil || line == "\r\n" || line == "\n" {
				break
			}
		}
		_, _ = conn.Write(bytes.Repeat([]byte("A"), 64<<10))
		time.Sleep(100 * time.Millisecond)
	}()

	host, portText, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("port: %v", err)
	}

	exiter := &Exiter{
		Targets:             []Target{{Host: "x.example", Port: 443, Path: "/"}},
		AllowPrivateTargets: true,
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := exiter.ExitIP(ctx, host, port, "", ""); err == nil {
		t.Fatal("ExitIP accepted an oversized CONNECT status line")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("oversized line was not rejected early: %s", elapsed)
	}
}
