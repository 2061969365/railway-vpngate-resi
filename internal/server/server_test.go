package server

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/probe"
)

func newClashServer(t *testing.T, status int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(newClashHandler(status, nil))
	t.Cleanup(server.Close)
	return server
}

func newClashHandler(status int, versionCalls *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		switch {
		case r.URL.Path == "/version":
			if versionCalls != nil {
				versionCalls.Add(1)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"version":"1.15.0"}`)
		case strings.HasPrefix(r.URL.Path, "/proxies/") && strings.HasSuffix(r.URL.Path, "/delay"):
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"delay":42}`)
		default:
			http.NotFound(w, r)
		}
	})
}

func newSlowClashHandler(status int, delay time.Duration, versionCalls *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		switch {
		case r.URL.Path == "/version":
			if versionCalls != nil {
				versionCalls.Add(1)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"version":"1.15.0"}`)
		case strings.HasPrefix(r.URL.Path, "/proxies/") && strings.HasSuffix(r.URL.Path, "/delay"):
			time.Sleep(delay)
			w.WriteHeader(status)
			_, _ = io.WriteString(w, `{"delay":42}`)
		default:
			http.NotFound(w, r)
		}
	})
}

func TestHealth(t *testing.T) {
	clash := newClashServer(t, http.StatusOK)
	handler := New(Options{Version: "test-version", Clash: &probe.ClashClient{BaseURL: clash.URL}})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var payload healthPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.OK || payload.Version != "test-version" || !payload.Clash {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestHealthWithoutClash(t *testing.T) {
	clash := newClashServer(t, http.StatusInternalServerError)
	handler := New(Options{Clash: &probe.ClashClient{BaseURL: clash.URL}})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/health", nil))
	var payload healthPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.OK || payload.Clash {
		t.Fatalf("payload = %+v", payload)
	}
}

func TestAuthMiddleware(t *testing.T) {
	handler := New(Options{Token: "s3cret"})
	tests := []struct {
		name   string
		header string
		want   int
	}{
		{name: "missing", want: http.StatusUnauthorized},
		{name: "wrong", header: "Bearer nope", want: http.StatusUnauthorized},
		{name: "raw token", header: "s3cret", want: http.StatusUnauthorized},
		{name: "correct", header: "Bearer s3cret", want: http.StatusOK},
		{name: "lowercase scheme", header: "bearer s3cret", want: http.StatusOK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
			if test.header != "" {
				request.Header.Set("Authorization", test.header)
			}
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, request)
			if recorder.Code != test.want {
				t.Fatalf("status = %d, want %d; body = %s", recorder.Code, test.want, recorder.Body)
			}
		})
	}
}

func TestMethodAndJSONValidation(t *testing.T) {
	handler := New(Options{})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/v1/exit", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("status = %d, allow = %q", recorder.Code, recorder.Header().Get("Allow"))
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/exit", strings.NewReader("{")))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("malformed json status = %d, body = %s", recorder.Code, recorder.Body)
	}

	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/exit", strings.NewReader(`{"host":"127.0.0.1","port":0}`)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("invalid port status = %d, body = %s", recorder.Code, recorder.Body)
	}
}

func TestRequestBodyCap(t *testing.T) {
	handler := New(Options{})
	body := strings.NewReader(strings.Repeat("a", maxRequestBody+1))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/exit", body))
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
}

func TestExitEndpointThroughFakeCONNECTProxy(t *testing.T) {
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "203.0.113.9\n")
	}))
	t.Cleanup(tlsServer.Close)
	proxy := newTestConnectProxy(t, tlsServer.Listener.Addr().String())
	host, port := proxy.address(t)
	pool := x509.NewCertPool()
	pool.AddCert(tlsServer.Certificate())

	handler := New(Options{
		Exit: &probe.Exiter{
			Targets:             []probe.Target{{Host: "exit.example", Port: 443, Path: "/"}},
			TLSConfig:           &tls.Config{RootCAs: pool, ServerName: "example.com"},
			AllowPrivateTargets: true,
		},
	})
	payload := fmt.Sprintf(`{"host":%q,"port":%d,"username":"u","password":"p","timeout_ms":3000}`, host, port)
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/exit", strings.NewReader(payload)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var response exitPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v; body = %s", err, recorder.Body)
	}
	if !response.OK || response.ExitIP != "203.0.113.9" || response.MS == nil || response.Target != "exit.example" {
		t.Fatalf("response = %+v", response)
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte("u:p"))
	if len(proxy.auth) != 1 || proxy.auth[0] != want {
		t.Fatalf("proxy auth = %v, want %q", proxy.auth, want)
	}
	if len(proxy.connects) != 1 || proxy.connects[0] != "CONNECT exit.example:443 HTTP/1.1" {
		t.Fatalf("connects = %v", proxy.connects)
	}
}

func TestExitEndpointFailureIs200(t *testing.T) {
	handler := New(Options{
		Exit: &probe.Exiter{
			Targets:             []probe.Target{{Host: "exit.example", Port: 443, Path: "/"}},
			AllowPrivateTargets: true,
		},
	})
	payload := `{"host":"127.0.0.1","port":1,"timeout_ms":250}`
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/exit", strings.NewReader(payload)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var response exitPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &response); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if response.OK || response.Error != "no exit ip" || response.MS != nil {
		t.Fatalf("response = %+v", response)
	}
}

func TestDelayEndpoint(t *testing.T) {
	clash := newClashServer(t, http.StatusOK)
	handler := New(Options{Clash: &probe.ClashClient{BaseURL: clash.URL}, Concurrency: 2})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay",
		strings.NewReader(`{"tags":["vpngate-1"],"timeout_ms":500}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var payload delayPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.OK || len(payload.Results) != 1 {
		t.Fatalf("payload = %+v", payload)
	}
	result := payload.Results[0]
	if result.Tag != "vpngate-1" || !result.Alive || result.MS == nil || *result.MS != 42 || result.Error != nil {
		t.Fatalf("result = %+v", result)
	}
}

func TestDelaySkipsVersionCheckWhenDelaysWork(t *testing.T) {
	var versionCalls atomic.Int64
	clash := httptest.NewServer(newClashHandler(http.StatusOK, &versionCalls))
	t.Cleanup(clash.Close)
	handler := New(Options{Clash: &probe.ClashClient{BaseURL: clash.URL}, Concurrency: 2})

	for attempt := 1; attempt <= 2; attempt++ {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay",
			strings.NewReader(`{"tags":["vpngate-1"],"timeout_ms":500}`)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("attempt %d status = %d, body = %s", attempt, recorder.Code, recorder.Body)
		}
		var payload delayPayload
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("attempt %d decode: %v", attempt, err)
		}
		if !payload.OK || len(payload.Results) != 1 || !payload.Results[0].Alive {
			t.Fatalf("attempt %d payload = %+v", attempt, payload)
		}
		if payload.Results[0].MS == nil || *payload.Results[0].MS != 42 {
			t.Fatalf("attempt %d result = %+v", attempt, payload.Results[0])
		}
	}

	if calls := versionCalls.Load(); calls != 0 {
		t.Fatalf("version calls = %d, want 0", calls)
	}
}

func TestDelayEndpointClashUnavailable(t *testing.T) {
	var versionCalls atomic.Int64
	clash := httptest.NewServer(newClashHandler(http.StatusInternalServerError, &versionCalls))
	t.Cleanup(clash.Close)
	handler := New(Options{Clash: &probe.ClashClient{BaseURL: clash.URL}})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay",
		strings.NewReader(`{"tags":["vpngate-1"]}`)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var payload errorPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if payload.OK || payload.Error != "clash unavailable" {
		t.Fatalf("payload = %+v", payload)
	}
	if calls := versionCalls.Load(); calls != 1 {
		t.Fatalf("version calls = %d, want 1", calls)
	}
}

func TestDelaySlowFailuresSkipVersionFallback(t *testing.T) {
	var versionCalls atomic.Int64
	clash := httptest.NewServer(newSlowClashHandler(
		http.StatusInternalServerError, 600*time.Millisecond, &versionCalls))
	t.Cleanup(clash.Close)
	handler := New(Options{Clash: &probe.ClashClient{BaseURL: clash.URL}})
	recorder := httptest.NewRecorder()
	started := time.Now()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay",
		strings.NewReader(`{"tags":["vpngate-1"],"timeout_ms":100}`)))
	elapsed := time.Since(started)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var payload delayPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.OK || len(payload.Results) != 1 {
		t.Fatalf("payload = %+v", payload)
	}
	result := payload.Results[0]
	if result.Tag != "vpngate-1" || result.Alive || result.Error == nil {
		t.Fatalf("result = %+v", result)
	}
	if calls := versionCalls.Load(); calls != 0 {
		t.Fatalf("version calls = %d, want 0", calls)
	}
	if elapsed >= 2*time.Second {
		t.Fatalf("elapsed = %s, want below the Python caller deadline", elapsed)
	}
}

func TestDelayEmptyTagsStillChecksClash(t *testing.T) {
	var versionCalls atomic.Int64
	clash := httptest.NewServer(newClashHandler(http.StatusOK, &versionCalls))
	t.Cleanup(clash.Close)
	handler := New(Options{Clash: &probe.ClashClient{BaseURL: clash.URL}})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay",
		strings.NewReader(`{"tags":[]}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var payload delayPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !payload.OK || len(payload.Results) != 0 {
		t.Fatalf("payload = %+v", payload)
	}
	if calls := versionCalls.Load(); calls != 1 {
		t.Fatalf("version calls = %d, want 1", calls)
	}
}

func TestDelayEndpointWithoutClash(t *testing.T) {
	handler := New(Options{})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay",
		strings.NewReader(`{"tags":["vpngate-1"]}`)))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
}

func TestExitRejectsNonLoopbackHost(t *testing.T) {
	handler := New(Options{Exit: &probe.Exiter{}})
	for _, host := range []string{"10.0.0.1", "192.168.1.10", "169.254.169.254", "8.8.8.8", "0.0.0.0"} {
		t.Run(host, func(t *testing.T) {
			payload := fmt.Sprintf(`{"host":%q,"port":3001,"timeout_ms":100}`, host)
			recorder := httptest.NewRecorder()
			handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/exit", strings.NewReader(payload)))
			if recorder.Code != http.StatusBadRequest {
				t.Fatalf("host %q status = %d, want 400; body = %s", host, recorder.Code, recorder.Body)
			}
		})
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/exit",
		strings.NewReader(`{"host":"localhost","port":1,"timeout_ms":100}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("loopback host rejected: status = %d, body = %s", recorder.Code, recorder.Body)
	}
}

func TestDelayRejectsTooManyTags(t *testing.T) {
	clash := newClashServer(t, http.StatusOK)
	handler := New(Options{Clash: &probe.ClashClient{BaseURL: clash.URL}})
	tags := make([]string, maxTags+1)
	for index := range tags {
		tags[index] = fmt.Sprintf("tag-%d", index)
	}
	body, err := json.Marshal(delayRequest{Tags: tags})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay", bytes.NewReader(body)))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400; body = %s", recorder.Code, recorder.Body)
	}
}

func TestDelayNormalizesTags(t *testing.T) {
	clash := newClashServer(t, http.StatusOK)
	handler := New(Options{Clash: &probe.ClashClient{BaseURL: clash.URL}})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay",
		strings.NewReader(`{"tags":["a","","a"," b "],"timeout_ms":500}`)))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", recorder.Code, recorder.Body)
	}
	var payload delayPayload
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(payload.Results) != 2 {
		t.Fatalf("results = %+v, want empty and duplicate tags removed", payload.Results)
	}
	if payload.Results[0].Tag != "a" || payload.Results[1].Tag != "b" {
		t.Fatalf("tags = %q/%q, want a/b", payload.Results[0].Tag, payload.Results[1].Tag)
	}
}

func TestDelayRejectsInvalidURL(t *testing.T) {
	clash := newClashServer(t, http.StatusOK)
	handler := New(Options{Clash: &probe.ClashClient{BaseURL: clash.URL}})
	rejected := []string{
		"http://example.com/generate_204",
		"ftp://127.0.0.1/generate_204",
		"file:///etc/passwd",
		"https://" + strings.Repeat("a", 3000) + ".com/",
	}
	for _, probeURL := range rejected {
		payload := fmt.Sprintf(`{"tags":["t"],"url":%q,"timeout_ms":100}`, probeURL)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay", strings.NewReader(payload)))
		if recorder.Code != http.StatusBadRequest {
			t.Fatalf("url %q status = %d, want 400; body = %s", probeURL, recorder.Code, recorder.Body)
		}
	}

	for _, probeURL := range []string{"https://example.com/generate_204", "http://127.0.0.1:8080/generate_204"} {
		payload := fmt.Sprintf(`{"tags":["t"],"url":%q,"timeout_ms":100}`, probeURL)
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/delay", strings.NewReader(payload)))
		if recorder.Code != http.StatusOK {
			t.Fatalf("url %q status = %d, want 200; body = %s", probeURL, recorder.Code, recorder.Body)
		}
	}
}

func TestNewClampsConcurrency(t *testing.T) {
	if handler := New(Options{Concurrency: 1000}); handler.concurrency != maxConcurrency {
		t.Fatalf("concurrency = %d, want %d", handler.concurrency, maxConcurrency)
	}
	if handler := New(Options{Concurrency: -1}); handler.concurrency != 8 {
		t.Fatalf("concurrency = %d, want default 8", handler.concurrency)
	}
}

type testConnectProxy struct {
	listener net.Listener
	backend  string
	mu       sync.Mutex
	auth     []string
	connects []string
}

func newTestConnectProxy(t *testing.T, backend string) *testConnectProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	proxy := &testConnectProxy{listener: listener, backend: backend}
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

func (p *testConnectProxy) address(t *testing.T) (string, int) {
	t.Helper()
	host, portText, err := net.SplitHostPort(p.listener.Addr().String())
	if err != nil {
		t.Fatalf("split: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	return host, port
}

func (p *testConnectProxy) handle(conn net.Conn) {
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
		if strings.HasPrefix(strings.ToLower(header), "proxy-authorization:") {
			_, value, _ := strings.Cut(header, ":")
			p.mu.Lock()
			p.auth = append(p.auth, strings.TrimSpace(value))
			p.mu.Unlock()
		}
	}
	upstream, err := net.Dial("tcp", p.backend)
	if err != nil {
		return
	}
	defer upstream.Close()
	if _, err := io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}
	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(upstream, &bufferedTestReader{reader: reader, conn: conn})
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite()
		}
		close(done)
	}()
	_, _ = io.Copy(conn, upstream)
	<-done
}

type bufferedTestReader struct {
	reader *bufio.Reader
	conn   net.Conn
}

func (r *bufferedTestReader) Read(p []byte) (int, error) {
	return r.reader.Read(p)
}
