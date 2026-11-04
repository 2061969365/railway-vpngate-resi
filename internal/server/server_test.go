package server

import (
	"bufio"
	"crypto/tls"
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
	"testing"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/probe"
)

func newClashServer(t *testing.T, versionStatus int) *httptest.Server {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "read only", http.StatusMethodNotAllowed)
			return
		}
		switch {
		case r.URL.Path == "/version":
			w.WriteHeader(versionStatus)
			_, _ = io.WriteString(w, `{"version":"1.15.0"}`)
		case strings.HasPrefix(r.URL.Path, "/proxies/") && strings.HasSuffix(r.URL.Path, "/delay"):
			_, _ = io.WriteString(w, `{"delay":42}`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return server
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

	handler := New(Options{
		Exit: &probe.Exiter{
			Targets:   []probe.Target{{Host: "exit.example", Port: 443, Path: "/"}},
			TLSConfig: &tls.Config{InsecureSkipVerify: true}, // local test certificate
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
			Targets:   []probe.Target{{Host: "exit.example", Port: 443, Path: "/"}},
			TLSConfig: &tls.Config{InsecureSkipVerify: true},
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

func TestDelayEndpointClashUnavailable(t *testing.T) {
	clash := newClashServer(t, http.StatusInternalServerError)
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
