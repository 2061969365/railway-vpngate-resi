package edge

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

type echoBackend struct {
	listener net.Listener
	echo     bool
	mu       sync.Mutex
	received []byte
}

func startEcho(t *testing.T) *echoBackend {
	t.Helper()
	return startBackend(t, true)
}

func startSink(t *testing.T) *echoBackend {
	t.Helper()
	return startBackend(t, false)
}

func startBackend(t *testing.T, echo bool) *echoBackend {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen backend: %v", err)
	}
	backend := &echoBackend{listener: listener, echo: echo}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go backend.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return backend
}

func (b *echoBackend) addr() string {
	return b.listener.Addr().String()
}

func (b *echoBackend) serve(conn net.Conn) {
	defer conn.Close()
	buffer := make([]byte, 4096)
	for {
		read, err := conn.Read(buffer)
		if read > 0 {
			b.mu.Lock()
			b.received = append(b.received, buffer[:read]...)
			b.mu.Unlock()
			if b.echo {
				if _, writeErr := conn.Write(buffer[:read]); writeErr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (b *echoBackend) bytesReceived() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.received...)
}

type tickerBackend struct {
	listener net.Listener
	interval time.Duration
	mu       sync.Mutex
	sent     int
}

func startTickerBackend(t *testing.T, interval time.Duration) *tickerBackend {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen ticker backend: %v", err)
	}
	backend := &tickerBackend{listener: listener, interval: interval}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go backend.serve(conn)
		}
	}()
	t.Cleanup(func() { _ = listener.Close() })
	return backend
}

func (b *tickerBackend) addr() string {
	return b.listener.Addr().String()
}

func (b *tickerBackend) bytesSent() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.sent
}

func (b *tickerBackend) serve(conn net.Conn) {
	defer conn.Close()
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, 4096)
		for {
			if _, err := conn.Read(buffer); err != nil {
				return
			}
		}
	}()

	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	chunk := []byte("tick")
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			if _, err := conn.Write(chunk); err != nil {
				return
			}
			b.mu.Lock()
			b.sent += len(chunk)
			b.mu.Unlock()
		}
	}
}

type adminRecord struct {
	method string
	uri    string
	body   string
}

func startAdmin(t *testing.T) (*httptest.Server, *[]adminRecord, *sync.Mutex) {
	t.Helper()
	records := &[]adminRecord{}
	mutex := &sync.Mutex{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		mutex.Lock()
		*records = append(*records, adminRecord{method: request.Method, uri: request.URL.RequestURI(), body: string(body)})
		mutex.Unlock()
		writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = io.WriteString(writer, "admin:"+request.Method+":"+request.URL.RequestURI()+":"+string(body))
	}))
	t.Cleanup(server.Close)
	return server, records, mutex
}

func testConfig(admin, node, chain, uuid string) Config {
	return Config{
		Listen:            "127.0.0.1:13000",
		AdminURL:          admin,
		NodeAddr:          node,
		ChainAddr:         chain,
		MetricsListen:     "127.0.0.1:39002",
		VLESSUUID:         uuid,
		DirectPath:        DefaultDirectPath,
		ChainPath:         DefaultChainPath,
		ResiPath:          DefaultResiPath,
		IdleTimeout:       5 * time.Second,
		DialTimeout:       2 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		MaxTunnels:        DefaultMaxTunnels,
		MaxHeaderBytes:    DefaultMaxHeaderBytes,
	}
}

func newTestProxy(t *testing.T, cfg Config) (*Proxy, *httptest.Server) {
	t.Helper()
	proxy, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	server := httptest.NewServer(proxy)
	t.Cleanup(server.Close)
	return proxy, server
}

func serverHost(t *testing.T, server *httptest.Server) string {
	t.Helper()
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}
	return parsed.Host
}

func openTunnel(t *testing.T, server *httptest.Server, path, payload string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", serverHost(t, server), 2*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	request := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: edge.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n%s", path, payload)
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write tunnel request: %v", err)
	}
	return conn
}

func finishTunnel(t *testing.T, conn net.Conn) []byte {
	t.Helper()
	tcp, ok := conn.(*net.TCPConn)
	if !ok {
		t.Fatalf("tunnel conn is %T, want *net.TCPConn", conn)
	}
	if err := tcp.CloseWrite(); err != nil {
		t.Fatalf("close write: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read tunnel response: %v", err)
	}
	_ = conn.Close()
	return data
}

func readUntil(t *testing.T, conn net.Conn, needle string) string {
	t.Helper()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	var builder strings.Builder
	buffer := make([]byte, 4096)
	for !strings.Contains(builder.String(), needle) {
		read, err := conn.Read(buffer)
		if read > 0 {
			builder.Write(buffer[:read])
		}
		if err != nil {
			break
		}
	}
	return builder.String()
}

func waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func TestDirectAndChainTunnelsAreCounted(t *testing.T) {
	node := startEcho(t)
	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	proxy, server := newTestProxy(t, testConfig(admin.URL, node.addr(), chain.addr(), "uuid"))

	directConn := openTunnel(t, server, "/ws-node?x=1", "PING-DIRECT")
	waitFor(t, "direct tunnel active", func() bool {
		snapshot := proxy.Metrics().Snapshot()
		return snapshot.Active == 1 && snapshot.Connections >= 1
	})
	directData := finishTunnel(t, directConn)
	waitFor(t, "direct tunnel closed", func() bool { return proxy.Metrics().Snapshot().Active == 0 })

	directReceived := node.bytesReceived()
	if !strings.Contains(string(directReceived), "/ws-node?x=1") || !strings.Contains(string(directReceived), "PING-DIRECT") {
		t.Fatalf("node backend did not receive the request: %q", directReceived)
	}
	if !strings.Contains(string(directData), "/ws-node?x=1") || !strings.Contains(string(directData), "PING-DIRECT") {
		t.Fatalf("client did not receive the echo: %q", directData)
	}
	afterDirect := proxy.Metrics().Snapshot()
	if afterDirect.BytesUp != uint64(len(directReceived)) {
		t.Fatalf("direct bytes_up = %d, want %d", afterDirect.BytesUp, len(directReceived))
	}
	if afterDirect.BytesDown != uint64(len(directData)) {
		t.Fatalf("direct bytes_down = %d, want %d", afterDirect.BytesDown, len(directData))
	}
	if afterDirect.Connections != 1 || afterDirect.Active != 0 {
		t.Fatalf("direct metrics = %+v", afterDirect)
	}

	chainConn := openTunnel(t, server, "/ws-chain", "PING-CHAIN")
	chainData := finishTunnel(t, chainConn)
	waitFor(t, "chain tunnel closed", func() bool { return proxy.Metrics().Snapshot().Active == 0 })
	chainReceived := chain.bytesReceived()
	if !strings.Contains(string(chainReceived), "/ws-chain") || !strings.Contains(string(chainReceived), "PING-CHAIN") {
		t.Fatalf("chain backend did not receive the request: %q", chainReceived)
	}
	if !strings.Contains(string(chainData), "PING-CHAIN") {
		t.Fatalf("client did not receive the chain echo: %q", chainData)
	}
	if len(node.bytesReceived()) != len(directReceived) {
		t.Fatal("direct echo backend received data again")
	}

	final := proxy.Metrics().Snapshot()
	wantUp := uint64(len(directReceived) + len(chainReceived))
	wantDown := uint64(len(directData) + len(chainData))
	if final.BytesUp != wantUp || final.BytesDown != wantDown {
		t.Fatalf("final bytes = up %d/down %d, want up %d/down %d", final.BytesUp, final.BytesDown, wantUp, wantDown)
	}
	if final.Connections != 2 || final.Active != 0 || !final.OK {
		t.Fatalf("final metrics = %+v", final)
	}
}

func TestStreamingPayloadCountedOnce(t *testing.T) {
	node := startEcho(t)
	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	proxy, server := newTestProxy(t, testConfig(admin.URL, node.addr(), chain.addr(), "uuid"))

	conn := openTunnel(t, server, "/ws-node", "")
	waitFor(t, "direct tunnel active", func() bool {
		return proxy.Metrics().Snapshot().Active == 1
	})
	waitFor(t, "request replay", func() bool {
		return strings.Contains(string(node.bytesReceived()), "\r\n\r\n")
	})
	requestBytes := len(node.bytesReceived())

	payload := "STREAM-AFTER-REPLAY"
	if _, err := io.WriteString(conn, payload); err != nil {
		t.Fatalf("write streaming payload: %v", err)
	}
	response := finishTunnel(t, conn)
	waitFor(t, "direct tunnel closed", func() bool {
		return proxy.Metrics().Snapshot().Active == 0
	})

	received := node.bytesReceived()
	wantUp := requestBytes + len(payload)
	if len(received) != wantUp {
		t.Fatalf("backend received %d bytes, want %d", len(received), wantUp)
	}
	if string(response) != string(received) {
		t.Fatalf("echoed %d bytes, backend received %d", len(response), len(received))
	}
	snapshot := proxy.Metrics().Snapshot()
	if snapshot.BytesUp != uint64(wantUp) {
		t.Fatalf("bytes_up = %d, want %d", snapshot.BytesUp, wantUp)
	}
	if snapshot.BytesDown != uint64(len(response)) {
		t.Fatalf("bytes_down = %d, want %d", snapshot.BytesDown, len(response))
	}
	if snapshot.Connections != 1 || !snapshot.OK {
		t.Fatalf("metrics = %+v", snapshot)
	}
	t.Logf("request=%d payload=%d echoed=%d bytes_up=%d bytes_down=%d",
		requestBytes, len(payload), len(response), snapshot.BytesUp, snapshot.BytesDown)
}

func TestOneWayTrafficSurvivesIdleTimeout(t *testing.T) {
	node := startTickerBackend(t, 20*time.Millisecond)
	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	cfg := testConfig(admin.URL, node.addr(), chain.addr(), "uuid")
	cfg.IdleTimeout = 150 * time.Millisecond
	proxy, server := newTestProxy(t, cfg)

	conn := openTunnel(t, server, "/ws-node", "")
	waitFor(t, "direct tunnel active", func() bool {
		return proxy.Metrics().Snapshot().Active == 1
	})

	start := time.Now()
	for time.Since(start) < 350*time.Millisecond {
		if active := proxy.Metrics().Snapshot().Active; active != 1 {
			t.Fatalf("one-way traffic tunnel closed after %s, active=%d", time.Since(start), active)
		}
		time.Sleep(10 * time.Millisecond)
	}
	sentBeforeClose := node.bytesSent()
	if sentBeforeClose == 0 {
		t.Fatal("ticker backend sent no data")
	}

	response := finishTunnel(t, conn)
	waitFor(t, "direct tunnel closed", func() bool {
		return proxy.Metrics().Snapshot().Active == 0
	})
	if len(response) < sentBeforeClose {
		t.Fatalf("client received %d bytes, backend sent at least %d", len(response), sentBeforeClose)
	}
	snapshot := proxy.Metrics().Snapshot()
	if snapshot.BytesDown != uint64(len(response)) {
		t.Fatalf("bytes_down = %d, want %d", snapshot.BytesDown, len(response))
	}
	if snapshot.Connections != 1 || snapshot.Active != 0 || !snapshot.OK {
		t.Fatalf("metrics = %+v", snapshot)
	}
	t.Logf("idle=%s survived=%s sent=%d received=%d bytes_up=%d bytes_down=%d",
		cfg.IdleTimeout, time.Since(start), sentBeforeClose, len(response), snapshot.BytesUp, snapshot.BytesDown)
}

func TestIdleTunnelClosesAfterTimeout(t *testing.T) {
	node := startSink(t)
	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	cfg := testConfig(admin.URL, node.addr(), chain.addr(), "uuid")
	cfg.IdleTimeout = 120 * time.Millisecond
	proxy, server := newTestProxy(t, cfg)

	start := time.Now()
	conn := openTunnel(t, server, "/ws-node", "")
	waitFor(t, "direct tunnel active", func() bool {
		return proxy.Metrics().Snapshot().Active == 1
	})

	time.Sleep(cfg.IdleTimeout / 2)
	if active := proxy.Metrics().Snapshot().Active; active != 1 {
		t.Fatalf("idle tunnel closed before the timeout, active=%d", active)
	}
	waitFor(t, "idle tunnel close", func() bool {
		return proxy.Metrics().Snapshot().Active == 0
	})
	elapsed := time.Since(start)
	if elapsed < cfg.IdleTimeout {
		t.Fatalf("idle tunnel closed after %s, want at least %s", elapsed, cfg.IdleTimeout)
	}

	snapshot := proxy.Metrics().Snapshot()
	if snapshot.BytesDown != 0 {
		t.Fatalf("idle sink tunnel bytes_down = %d, want 0", snapshot.BytesDown)
	}
	if snapshot.BytesUp != uint64(len(node.bytesReceived())) {
		t.Fatalf("bytes_up = %d, backend received %d", snapshot.BytesUp, len(node.bytesReceived()))
	}
	if snapshot.Connections != 1 || snapshot.Active != 0 || !snapshot.OK {
		t.Fatalf("metrics = %+v", snapshot)
	}

	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("idle tunnel client connection is still open")
	}
	t.Logf("idle=%s closed_after=%s bytes_up=%d bytes_down=%d",
		cfg.IdleTimeout, elapsed, snapshot.BytesUp, snapshot.BytesDown)
}

func TestResiIsRawToAdminAndNotCounted(t *testing.T) {
	node := startEcho(t)
	chain := startEcho(t)
	admin, records, mutex := startAdmin(t)
	proxy, server := newTestProxy(t, testConfig(admin.URL, node.addr(), chain.addr(), "uuid"))

	conn, err := net.DialTimeout("tcp", serverHost(t, server), 2*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	defer conn.Close()
	request := "GET /ws-resi?x=1 HTTP/1.1\r\nHost: edge.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write resi: %v", err)
	}
	response := readUntil(t, conn, "admin:GET:/ws-resi?x=1:")
	if !strings.Contains(response, "admin:GET:/ws-resi?x=1:") {
		t.Fatalf("resi response = %q", response)
	}
	mutex.Lock()
	got := append([]adminRecord(nil), (*records)...)
	mutex.Unlock()
	if len(got) != 1 || got[0].uri != "/ws-resi?x=1" {
		t.Fatalf("admin records = %+v", got)
	}
	snapshot := proxy.Metrics().Snapshot()
	if snapshot.BytesUp != 0 || snapshot.BytesDown != 0 || snapshot.Connections != 0 || snapshot.Active != 0 {
		t.Fatalf("resi must not be counted: %+v", snapshot)
	}
}

func TestOtherPathsFallBackToAdmin(t *testing.T) {
	node := startEcho(t)
	chain := startEcho(t)
	admin, records, mutex := startAdmin(t)
	_, server := newTestProxy(t, testConfig(admin.URL, node.addr(), chain.addr(), "uuid"))

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Get(server.URL + "/api/status?x=1")
	if err != nil {
		t.Fatalf("GET admin path: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || !strings.Contains(string(body), "admin:GET:/api/status?x=1:") {
		t.Fatalf("admin response = %d %q", response.StatusCode, body)
	}
	mutex.Lock()
	got := append([]adminRecord(nil), (*records)...)
	mutex.Unlock()
	if len(got) != 1 || got[0].method != http.MethodGet || got[0].uri != "/api/status?x=1" {
		t.Fatalf("admin records = %+v", got)
	}
}

func TestEmptyUUIDFallsBackToAdmin(t *testing.T) {
	node := startEcho(t)
	chain := startEcho(t)
	admin, records, mutex := startAdmin(t)
	proxy, server := newTestProxy(t, testConfig(admin.URL, node.addr(), chain.addr(), ""))

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	response, err := client.Get(server.URL + "/ws-node")
	if err != nil {
		t.Fatalf("GET node path: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(body), "admin:GET:/ws-node:") {
		t.Fatalf("admin response = %q", body)
	}
	if len(node.bytesReceived()) != 0 {
		t.Fatal("node backend was reached although VLESS_UUID is empty")
	}
	mutex.Lock()
	got := len(*records)
	mutex.Unlock()
	if got != 1 {
		t.Fatalf("admin requests = %d, want 1", got)
	}
	snapshot := proxy.Metrics().Snapshot()
	if snapshot.Connections != 0 || snapshot.BytesUp != 0 || snapshot.BytesDown != 0 {
		t.Fatalf("fallback must not be counted: %+v", snapshot)
	}
}

func TestGETWithBodyFallsBackToAdmin(t *testing.T) {
	node := startEcho(t)
	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	_, server := newTestProxy(t, testConfig(admin.URL, node.addr(), chain.addr(), "uuid"))

	client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
	request, err := http.NewRequest(http.MethodGet, server.URL+"/ws-node", strings.NewReader("HELLO"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("GET with body: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if !strings.Contains(string(body), "admin:GET:/ws-node:HELLO") {
		t.Fatalf("admin response = %q", body)
	}
	if len(node.bytesReceived()) != 0 {
		t.Fatal("bodyless routing was applied to a GET with a body")
	}
}

func TestRawDialFailureIs502(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddress := closed.Addr().String()
	_ = closed.Close()

	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	proxy, server := newTestProxy(t, testConfig(admin.URL, deadAddress, chain.addr(), "uuid"))

	conn := openTunnel(t, server, "/ws-node", "")
	response := string(finishTunnel(t, conn))
	if !strings.Contains(response, "502 Bad Gateway") {
		t.Fatalf("response = %q, want 502", response)
	}
	snapshot := proxy.Metrics().Snapshot()
	if snapshot.Connections != 0 || snapshot.BytesUp != 0 || snapshot.BytesDown != 0 || snapshot.Active != 0 {
		t.Fatalf("failed dial must not be counted: %+v", snapshot)
	}
}

func TestRawDialFailureWithBufferedDataCloses(t *testing.T) {
	closed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddress := closed.Addr().String()
	_ = closed.Close()

	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	_, server := newTestProxy(t, testConfig(admin.URL, deadAddress, chain.addr(), "uuid"))

	conn := openTunnel(t, server, "/ws-node", "EARLY-DATA")
	response := string(finishTunnel(t, conn))
	if !strings.Contains(response, "502 Bad Gateway") {
		t.Fatalf("response = %q, want 502", response)
	}
	if strings.Contains(response, "400 Bad Request") {
		t.Fatalf("leftover tunnel bytes were parsed as a second request: %q", response)
	}
}

func TestMetricsHandler(t *testing.T) {
	metrics := &Metrics{}
	server := httptest.NewServer(metrics)
	t.Cleanup(server.Close)

	response, err := http.Get(server.URL + "/v1/traffic")
	if err != nil {
		t.Fatalf("GET traffic: %v", err)
	}
	var empty Traffic
	if err := json.NewDecoder(response.Body).Decode(&empty); err != nil {
		t.Fatalf("decode empty traffic: %v", err)
	}
	response.Body.Close()
	if !empty.OK || empty.BytesUp != 0 || empty.BytesDown != 0 || empty.Connections != 0 || empty.Active != 0 {
		t.Fatalf("empty traffic = %+v", empty)
	}

	metrics.bytesUp.Add(11)
	metrics.bytesDown.Add(22)
	metrics.connections.Add(3)
	metrics.active.Add(2)
	response, err = http.Get(server.URL + "/v1/traffic")
	if err != nil {
		t.Fatalf("GET traffic: %v", err)
	}
	var traffic Traffic
	if err := json.NewDecoder(response.Body).Decode(&traffic); err != nil {
		t.Fatalf("decode traffic: %v", err)
	}
	response.Body.Close()
	want := Traffic{OK: true, BytesUp: 11, BytesDown: 22, Connections: 3, Active: 2}
	if traffic != want {
		t.Fatalf("traffic = %+v, want %+v", traffic, want)
	}

	response, err = http.Get(server.URL + "/healthz")
	if err != nil {
		t.Fatalf("GET healthz: %v", err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "ok" {
		t.Fatalf("healthz = %d %q", response.StatusCode, body)
	}

	response, err = http.Post(server.URL+"/v1/traffic", "text/plain", strings.NewReader(""))
	if err != nil {
		t.Fatalf("POST traffic: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("POST traffic status = %d, want 405", response.StatusCode)
	}
}

func TestValidateMetricsListen(t *testing.T) {
	allowed := []string{"127.0.0.1:39002", "localhost:39002", "[::1]:39002", "127.0.0.2:1"}
	for _, listen := range allowed {
		if err := ValidateMetricsListen(listen); err != nil {
			t.Fatalf("ValidateMetricsListen(%q) = %v, want nil", listen, err)
		}
	}
	rejected := []string{"0.0.0.0:39002", ":39002", "192.0.2.1:39002", "example.com:39002", "not-an-address"}
	for _, listen := range rejected {
		if err := ValidateMetricsListen(listen); err == nil {
			t.Fatalf("ValidateMetricsListen(%q) = nil, want error", listen)
		}
	}
}

func TestNewRejectsInvalidAdminURL(t *testing.T) {
	cases := []string{"127.0.0.1:3001", "ftp://127.0.0.1:3001", "http://"}
	for _, adminURL := range cases {
		if _, err := New(testConfig(adminURL, "127.0.0.1:1", "127.0.0.1:2", "uuid"), log.New(io.Discard, "", 0)); err == nil {
			t.Fatalf("New accepted invalid EDGE_ADMIN %q", adminURL)
		}
	}
}

func TestAdminTransportKeepsIdleConnections(t *testing.T) {
	admin, _, _ := startAdmin(t)
	proxy, _ := newTestProxy(t, testConfig(admin.URL, "127.0.0.1:1", "127.0.0.1:2", "uuid"))
	transport, ok := proxy.reverse.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("admin transport is %T, want *http.Transport", proxy.reverse.Transport)
	}
	if transport.MaxIdleConnsPerHost != adminMaxIdleConnsPerHost {
		t.Fatalf("MaxIdleConnsPerHost = %d, want %d", transport.MaxIdleConnsPerHost, adminMaxIdleConnsPerHost)
	}
}

func TestCopyBufferPoolProvidesFullBuffers(t *testing.T) {
	buffer := copyBufferPool.Get().([]byte)
	if len(buffer) != copyBufferSize {
		t.Fatalf("pooled buffer len = %d, want %d", len(buffer), copyBufferSize)
	}
	copyBufferPool.Put(buffer)
}

func TestTunnelLimitRejectsWith503(t *testing.T) {
	node := startEcho(t)
	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	cfg := testConfig(admin.URL, node.addr(), chain.addr(), "uuid")
	cfg.MaxTunnels = 1
	proxy, server := newTestProxy(t, cfg)

	first := openTunnel(t, server, "/ws-node", "")
	waitFor(t, "first tunnel active", func() bool {
		return proxy.Metrics().Snapshot().Tunnels == 1
	})

	conn, err := net.DialTimeout("tcp", serverHost(t, server), 2*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	if _, err := io.WriteString(conn, "GET /ws-node HTTP/1.1\r\nHost: edge.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"); err != nil {
		t.Fatalf("write second tunnel: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response, err := io.ReadAll(conn)
	_ = conn.Close()
	if err != nil {
		t.Fatalf("read 503 response: %v", err)
	}
	if !strings.Contains(string(response), "503 Service Unavailable") {
		t.Fatalf("response = %q, want 503", response)
	}
	if !strings.Contains(string(response), "Connection: close") {
		t.Fatalf("response = %q, want Connection: close", response)
	}
	snapshot := proxy.Metrics().Snapshot()
	if snapshot.Rejected < 1 || snapshot.MaxTunnels != 1 {
		t.Fatalf("metrics after rejection = %+v", snapshot)
	}

	_ = first.Close()
	waitFor(t, "tunnel slot released", func() bool {
		return proxy.Metrics().Snapshot().Tunnels == 0
	})

	third := openTunnel(t, server, "/ws-node", "AFTER-REJECT")
	thirdData := finishTunnel(t, third)
	if !strings.Contains(string(thirdData), "AFTER-REJECT") {
		t.Fatalf("third tunnel did not pass after the slot was released: %q", thirdData)
	}
}

func TestCloseTunnelsClosesActiveTunnel(t *testing.T) {
	node := startSink(t)
	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	proxy, server := newTestProxy(t, testConfig(admin.URL, node.addr(), chain.addr(), "uuid"))

	conn := openTunnel(t, server, "/ws-node", "")
	waitFor(t, "tunnel tracked", func() bool {
		proxy.tunnelsMu.Lock()
		defer proxy.tunnelsMu.Unlock()
		return len(proxy.tunnels) == 1
	})
	if closed := proxy.CloseTunnels(); closed != 1 {
		t.Fatalf("CloseTunnels() = %d, want 1", closed)
	}
	waitFor(t, "tunnel released", func() bool {
		return proxy.Metrics().Snapshot().Tunnels == 0
	})
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("CloseTunnels left the client connection open")
	}
}

func TestNewRejectsRemoteAdminUnlessAllowed(t *testing.T) {
	cfg := testConfig("http://203.0.113.5:3001", "127.0.0.1:1", "127.0.0.1:2", "uuid")
	if _, err := New(cfg, log.New(io.Discard, "", 0)); err == nil {
		t.Fatal("New accepted a remote EDGE_ADMIN without the escape")
	}
	cfg.AllowRemoteAdmin = true
	if _, err := New(cfg, log.New(io.Discard, "", 0)); err != nil {
		t.Fatalf("EDGE_ADMIN_ALLOW_REMOTE escape was ignored: %v", err)
	}
}

func TestNewAcceptsLocalhostAdmin(t *testing.T) {
	if _, err := New(testConfig("http://localhost:3001", "127.0.0.1:1", "127.0.0.1:2", "uuid"),
		log.New(io.Discard, "", 0)); err != nil {
		t.Fatalf("New(localhost admin) = %v", err)
	}
}

func TestNewRejectsHTTPSAdmin(t *testing.T) {
	_, err := New(testConfig("https://user:secret@127.0.0.1:3001", "127.0.0.1:1", "127.0.0.1:2", "uuid"), log.New(io.Discard, "", 0))
	if err == nil {
		t.Fatal("New accepted an https EDGE_ADMIN although the raw tunnel is plaintext")
	}
	if !strings.Contains(err.Error(), "http") {
		t.Fatalf("error = %q, want a hint that http is required", err)
	}
	if strings.Contains(err.Error(), "secret") {
		t.Fatalf("error leaked the admin password: %q", err)
	}
}

func TestRawPathRequiresWebSocketUpgrade(t *testing.T) {
	node := startEcho(t)
	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	proxy, server := newTestProxy(t, testConfig(admin.URL, node.addr(), chain.addr(), "uuid"))

	requests := []string{
		"GET /ws-node HTTP/1.1\r\nHost: edge.test\r\nConnection: close\r\n\r\n",
		"GET /ws-node HTTP/1.1\r\nHost: edge.test\r\nConnection: Upgrade\r\n\r\n",
		"GET /ws-node HTTP/1.1\r\nHost: edge.test\r\nUpgrade: websocket\r\n\r\n",
	}
	for _, request := range requests {
		conn, err := net.DialTimeout("tcp", serverHost(t, server), 2*time.Second)
		if err != nil {
			t.Fatalf("dial edge: %v", err)
		}
		if _, err := io.WriteString(conn, request); err != nil {
			t.Fatalf("write: %v", err)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		response, _ := io.ReadAll(conn)
		_ = conn.Close()
		if !strings.Contains(string(response), "400 Bad Request") {
			t.Fatalf("request %q -> %q, want 400", request, response)
		}
	}
	if snapshot := proxy.Metrics().Snapshot(); snapshot.Tunnels != 0 || snapshot.Connections != 0 {
		t.Fatalf("rejected requests must not open a tunnel: %+v", snapshot)
	}
}

func TestRawReplayStripsHopByHopHeaders(t *testing.T) {
	node := startEcho(t)
	chain := startEcho(t)
	admin, _, _ := startAdmin(t)
	_, server := newTestProxy(t, testConfig(admin.URL, node.addr(), chain.addr(), "uuid"))

	conn, err := net.DialTimeout("tcp", serverHost(t, server), 2*time.Second)
	if err != nil {
		t.Fatalf("dial edge: %v", err)
	}
	request := "GET /ws-node HTTP/1.1\r\nHost: edge.test\r\n" +
		"Connection: Upgrade\r\nUpgrade: websocket\r\n" +
		"Proxy-Connection: keep-alive\r\nKeep-Alive: timeout=9\r\n" +
		"TE: trailers\r\nTrailer: X-Checksum\r\nX-Keep: yes\r\n\r\nRAW"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write: %v", err)
	}
	waitFor(t, "replayed request", func() bool {
		return strings.Contains(string(node.bytesReceived()), "RAW")
	})
	_ = conn.Close()
	received := string(node.bytesReceived())
	for _, banned := range []string{"Proxy-Connection", "Keep-Alive", "TE:", "Trailer:"} {
		if strings.Contains(received, banned) {
			t.Fatalf("hop-by-hop header %q reached the backend:\n%s", banned, received)
		}
	}
	if !strings.Contains(received, "Upgrade: websocket") || !strings.Contains(received, "X-Keep: yes") {
		t.Fatalf("upgrade/end-to-end headers were lost:\n%s", received)
	}
}

func startRealEdge(t *testing.T, cfg Config) (*Proxy, string) {
	t.Helper()
	admin, _, _ := startAdmin(t)
	cfg.AdminURL = admin.URL
	proxy, err := New(cfg, log.New(io.Discard, "", 0))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout,
		MaxHeaderBytes:    cfg.MaxHeaderBytes,
	}
	go func() { _ = server.Serve(proxy.WrapListener(listener)) }()
	t.Cleanup(func() { _ = server.Close() })
	return proxy, listener.Addr().String()
}

func TestMaxConnsRejectsExtraAndHealthzRecovers(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1", "127.0.0.1:1", "127.0.0.1:2", "uuid")
	cfg.MaxConns = 4
	proxy, address := startRealEdge(t, cfg)

	conns := make([]net.Conn, 0, cfg.MaxConns)
	for index := 0; index < cfg.MaxConns; index++ {
		conn, err := net.DialTimeout("tcp", address, 2*time.Second)
		if err != nil {
			t.Fatalf("dial idle conn %d: %v", index, err)
		}
		conns = append(conns, conn)
	}
	waitFor(t, "max conns active", func() bool {
		return proxy.Metrics().Snapshot().ActiveConns == int64(cfg.MaxConns)
	})

	extra, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial extra: %v", err)
	}
	_ = extra.SetReadDeadline(time.Now().Add(2 * time.Second))
	buffer := make([]byte, 1)
	if _, err := extra.Read(buffer); err == nil {
		t.Fatal("over-limit connection was not closed")
	}
	_ = extra.Close()
	if snapshot := proxy.Metrics().Snapshot(); snapshot.ConnRejected < 1 {
		t.Fatalf("conn rejected metric = %+v", snapshot)
	}

	for _, conn := range conns {
		_ = conn.Close()
	}
	waitFor(t, "conn slots released", func() bool {
		return proxy.Metrics().Snapshot().ActiveConns == 0
	})
	response, err := http.Get("http://" + address + "/healthz")
	if err != nil {
		t.Fatalf("healthz: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("healthz status = %d", response.StatusCode)
	}
}

func TestServerReadHeaderTimeoutClosesSlowHeaders(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1", "127.0.0.1:1", "127.0.0.1:2", "uuid")
	cfg.ReadHeaderTimeout = 200 * time.Millisecond
	cfg.MaxHeaderBytes = 8 << 10
	_, address := startRealEdge(t, cfg)

	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "GET /healthz HTTP/1.1\r\nHost: edge.test\r\n"); err != nil {
		t.Fatalf("write partial headers: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	start := time.Now()
	response, _ := io.ReadAll(conn)
	elapsed := time.Since(start)
	if elapsed > 1500*time.Millisecond {
		t.Fatalf("slow headers were not bounded: %s", elapsed)
	}
	if len(response) > 0 && !strings.Contains(string(response), "408") &&
		!strings.Contains(string(response), "400") {
		t.Fatalf("unexpected slow-header response = %q", response)
	}
}

func TestServerMaxHeaderBytesRejectsOversizedHeaders(t *testing.T) {
	cfg := testConfig("http://127.0.0.1:1", "127.0.0.1:1", "127.0.0.1:2", "uuid")
	cfg.ReadHeaderTimeout = 2 * time.Second
	cfg.MaxHeaderBytes = 8 << 10
	_, address := startRealEdge(t, cfg)

	conn, err := net.DialTimeout("tcp", address, 2*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	request := "GET /healthz HTTP/1.1\r\nHost: edge.test\r\nX-Big: " +
		strings.Repeat("a", 16<<10) + "\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write oversized headers: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response, _ := io.ReadAll(conn)
	if !strings.Contains(string(response), "431") && !strings.Contains(string(response), "400") {
		t.Fatalf("oversized header response = %q", response)
	}
}

func TestRedactedAdminURL(t *testing.T) {
	got := RedactedAdminURL("http://user:secret@127.0.0.1:3001")
	if strings.Contains(got, "secret") || !strings.Contains(got, "127.0.0.1:3001") {
		t.Fatalf("RedactedAdminURL = %q", got)
	}
}
