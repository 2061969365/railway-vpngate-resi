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
		Listen:        "127.0.0.1:0",
		AdminURL:      admin,
		NodeAddr:      node,
		ChainAddr:     chain,
		MetricsListen: "127.0.0.1:0",
		VLESSUUID:     uuid,
		DirectPath:    DefaultDirectPath,
		ChainPath:     DefaultChainPath,
		ResiPath:      DefaultResiPath,
		IdleTimeout:   5 * time.Second,
		DialTimeout:   2 * time.Second,
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
	request := "GET /ws-resi?x=1 HTTP/1.1\r\nHost: edge.test\r\nConnection: close\r\n\r\n"
	if _, err := io.WriteString(conn, request); err != nil {
		t.Fatalf("write resi: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("read resi: %v", err)
	}
	if !strings.Contains(string(response), "admin:GET:/ws-resi?x=1:") {
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

	response, err := http.Get(server.URL + "/ws-node")
	if err != nil {
		t.Fatalf("GET node: %v", err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusBadGateway {
		t.Fatalf("status = %d, want 502", response.StatusCode)
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
