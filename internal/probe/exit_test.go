package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
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

func newExitBackend(t *testing.T, handler http.HandlerFunc) (*httptest.Server, *sniRecorder) {
	t.Helper()
	recorder := &sniRecorder{}
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			recorder.record(hello.ServerName)
			return nil, nil
		},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	return server, recorder
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
	backend, sni := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
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
		TLSConfig: &tls.Config{InsecureSkipVerify: true}, // local test certificate
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
	backend, _ := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "198.51.100.7")
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()

	exiter := &Exiter{
		Targets:   []Target{{Host: "only.example", Port: 443, Path: "/"}},
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
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
	backend, _ := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
		}
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	host, port := proxy.addr()

	exiter := &Exiter{
		Targets:   []Target{{Host: "slow.example", Port: 443, Path: "/"}},
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
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
	backend, _ := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
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
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
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
	backend, _ := newExitBackend(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "192.0.2.1")
	})
	proxy := newFakeProxy(t, backend.Listener.Addr().String())
	proxy.setStatus("407 Proxy Authentication Required")
	host, port := proxy.addr()

	exiter := &Exiter{
		Targets:   []Target{{Host: "only.example", Port: 443, Path: "/"}},
		TLSConfig: &tls.Config{InsecureSkipVerify: true},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := exiter.ExitIP(ctx, host, port, "u", "p"); err == nil {
		t.Fatal("ExitIP accepted a rejected CONNECT")
	}
}
