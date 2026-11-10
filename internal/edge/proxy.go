package edge

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	copyBufferSize           = 32 * 1024
	adminMaxIdleConnsPerHost = 32
	// replayWriteTimeout bounds the Request.Write replay of the hijacked
	// request headers into the backend. Without it a backend that accepts TCP
	// but never reads wedges the handler, both fds and two goroutines forever.
	replayWriteTimeout = 5 * time.Second
)

var copyBufferPool = sync.Pool{
	New: func() any { return make([]byte, copyBufferSize) },
}

// Proxy is the public data-plane HTTP handler.
type Proxy struct {
	cfg      Config
	logger   *log.Logger
	metrics  *Metrics
	reverse  *httputil.ReverseProxy
	adminTCP string

	tunnelSlots chan struct{}
	tunnelsMu   sync.Mutex
	tunnels     map[net.Conn]struct{}
}

// New validates the configuration and builds the proxy handler.
func New(cfg Config, logger *log.Logger) (*Proxy, error) {
	admin, err := url.Parse(cfg.AdminURL)
	if err != nil {
		return nil, fmt.Errorf("EDGE_ADMIN %q: %w", cfg.AdminURL, err)
	}
	if admin.Scheme != "http" {
		// /ws-resi replays the hijacked request as plaintext over a raw TCP
		// connection, so an https admin URL can never work for that path.
		return nil, fmt.Errorf("EDGE_ADMIN %q must use http: the /ws-resi raw tunnel is plaintext and https is unsupported", admin.Redacted())
	}
	if admin.Host == "" {
		return nil, fmt.Errorf("EDGE_ADMIN %q has no host", admin.Redacted())
	}
	if !cfg.AllowRemoteAdmin {
		if err := ValidateAdminHost(admin.Hostname()); err != nil {
			return nil, err
		}
	}
	if admin.Path != "" && admin.Path != "/" {
		return nil, fmt.Errorf("EDGE_ADMIN %q must not carry a path: the raw tunnel ignores it", admin.Redacted())
	}
	if admin.RawQuery != "" || admin.Fragment != "" {
		return nil, fmt.Errorf("EDGE_ADMIN %q must not carry a query or fragment", admin.Redacted())
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = time.Duration(DefaultDialTimeoutMS) * time.Millisecond
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = time.Duration(DefaultIdleTimeoutMS) * time.Millisecond
	}
	if cfg.ReadHeaderTimeout <= 0 {
		cfg.ReadHeaderTimeout = time.Duration(DefaultReadHeaderTimeoutMS) * time.Millisecond
	}
	if cfg.MaxTunnels <= 0 {
		cfg.MaxTunnels = DefaultMaxTunnels
	}
	if cfg.MaxTunnels > MaxMaxTunnels {
		cfg.MaxTunnels = MaxMaxTunnels
	}
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = DefaultMaxConns
	}
	if cfg.MaxConns > MaxMaxConns {
		cfg.MaxConns = MaxMaxConns
	}
	if cfg.MaxHeaderBytes <= 0 {
		cfg.MaxHeaderBytes = DefaultMaxHeaderBytes
	}
	if cfg.MaxHeaderBytes > MaxMaxHeaderBytes {
		cfg.MaxHeaderBytes = MaxMaxHeaderBytes
	}
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if logger == nil {
		logger = log.New(os.Stderr, "vpngate-edge: ", log.LstdFlags)
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   adminMaxIdleConnsPerHost,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
	}
	reverse := httputil.NewSingleHostReverseProxy(admin)
	reverse.Transport = transport
	reverse.ErrorLog = logger
	reverse.ErrorHandler = func(writer http.ResponseWriter, request *http.Request, proxyErr error) {
		logger.Printf("admin proxy %s failed: %v", request.URL.Path, proxyErr)
		http.Error(writer, "bad gateway", http.StatusBadGateway)
	}

	return &Proxy{
		cfg:         cfg,
		logger:      logger,
		metrics:     &Metrics{maxTunnels: cfg.MaxTunnels, maxConns: cfg.MaxConns},
		reverse:     reverse,
		adminTCP:    adminAddress(admin),
		tunnelSlots: make(chan struct{}, cfg.MaxTunnels),
		tunnels:     make(map[net.Conn]struct{}),
	}, nil
}

// Metrics returns the counters served on the metrics listener.
func (p *Proxy) Metrics() *Metrics {
	return p.metrics
}

// RedactedAdminURL hides credentials embedded in EDGE_ADMIN before logging.
func RedactedAdminURL(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "<invalid EDGE_ADMIN>"
	}
	return parsed.Redacted()
}

// ServeHTTP routes one public request.
func (p *Proxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if isBodylessGet(request) {
		var backend string
		count := false
		switch {
		case p.cfg.VLESSUUID != "" && request.URL.Path == p.cfg.DirectPath:
			backend, count = p.cfg.NodeAddr, true
		case p.cfg.VLESSUUID != "" && request.URL.Path == p.cfg.ChainPath:
			backend, count = p.cfg.ChainAddr, true
		case request.URL.Path == p.cfg.ResiPath:
			backend = p.adminTCP
		}
		if backend != "" {
			// A raw path is only ever a WebSocket upgrade. A plain GET used to
			// occupy a tunnel slot and reach the backend; reject it before
			// dialing instead (R2-5-08).
			if !isWebSocketUpgrade(request) {
				writer.Header().Set("Connection", "close")
				http.Error(writer, "websocket upgrade required", http.StatusBadRequest)
				return
			}
			p.serveRaw(writer, request, backend, count)
			return
		}
	}
	p.reverse.ServeHTTP(writer, request)
}

// hopByHopHeaders are never forwarded to the raw backend. The WebSocket
// handshake headers are re-added explicitly after stripping, so a caller
// cannot smuggle proxy-only headers (`Proxy-Connection`, `Keep-Alive`, ...)
// into the backend while the upgrade itself still works.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "TE", "Trailer", "Transfer-Encoding", "Upgrade",
}

func sanitizedReplay(request *http.Request) *http.Request {
	clone := request.Clone(request.Context())
	clone.Header = request.Header.Clone()
	// RFC 7230: every header named by Connection is hop-by-hop too.
	for _, value := range request.Header.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				clone.Header.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		clone.Header.Del(name)
	}
	clone.Header.Set("Connection", "Upgrade")
	clone.Header.Set("Upgrade", "websocket")
	clone.Close = false
	return clone
}

func isBodylessGet(request *http.Request) bool {
	return request.Method == http.MethodGet &&
		request.ContentLength == 0 &&
		len(request.TransferEncoding) == 0
}

func isWebSocketUpgrade(request *http.Request) bool {
	if !headerHasToken(request.Header, "Connection", "upgrade") {
		return false
	}
	return headerHasToken(request.Header, "Upgrade", "websocket")
}

func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

// serveRaw hijacks the client connection and tunnels it to backendAddr. The
// original request is replayed with Request.Write so the backend sees the same
// headers and path; buffered bytes the HTTP server already read are forwarded
// before the bidirectional copy starts.
func (p *Proxy) serveRaw(writer http.ResponseWriter, request *http.Request, backendAddr string, count bool) {
	if !p.acquireTunnel() {
		writer.Header().Set("Connection", "close")
		http.Error(writer, "too many tunnels", http.StatusServiceUnavailable)
		return
	}
	defer p.releaseTunnel()

	dialer := &net.Dialer{Timeout: p.cfg.DialTimeout, KeepAlive: 30 * time.Second}
	backend, err := dialer.Dial("tcp", backendAddr)
	if err != nil {
		p.logger.Printf("raw backend %s dial failed: %v", backendAddr, err)
		writer.Header().Set("Connection", "close")
		http.Error(writer, "bad gateway", http.StatusBadGateway)
		return
	}

	hijacker, ok := writer.(http.Hijacker)
	if !ok {
		_ = backend.Close()
		p.logger.Printf("raw backend %s: response writer does not support hijacking", backendAddr)
		http.Error(writer, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	client, clientBuffer, err := hijacker.Hijack()
	if err != nil {
		_ = backend.Close()
		p.logger.Printf("hijack failed: %v", err)
		return
	}
	defer client.Close()
	defer backend.Close()
	p.trackTunnel(client)
	defer p.untrackTunnel(client)

	var backendWriter io.Writer = backend
	var clientWriter io.Writer = client
	if count {
		p.metrics.connections.Add(1)
		p.metrics.active.Add(1)
		defer p.metrics.active.Add(-1)
		backendWriter = &countingWriter{Conn: backend, counter: &p.metrics.bytesUp}
		clientWriter = &countingWriter{Conn: client, counter: &p.metrics.bytesDown}
	}

	activity := newTunnelActivity()
	closeBoth := newCloseBoth(client, backend)
	stopWatchdog := p.startTunnelWatchdog(activity, closeBoth)
	defer stopWatchdog()

	// The replay runs under the watchdog and a write deadline so a backend that
	// accepts TCP but stops reading cannot hold the tunnel forever.
	if err := backend.SetWriteDeadline(time.Now().Add(replayWriteTimeout)); err != nil {
		p.logger.Printf("raw backend %s write deadline: %v", backendAddr, err)
	}
	if err := sanitizedReplay(request).Write(backendWriter); err != nil {
		p.logger.Printf("raw backend %s request write failed: %v", backendAddr, err)
		closeBoth()
		return
	}
	activity.touch()
	if buffered := clientBuffer.Reader.Buffered(); buffered > 0 {
		if _, err := io.CopyN(backendWriter, clientBuffer.Reader, int64(buffered)); err != nil {
			p.logger.Printf("raw backend %s buffered write failed: %v", backendAddr, err)
			closeBoth()
			return
		}
		activity.touch()
	}
	_ = backend.SetWriteDeadline(time.Time{})

	clientReader := &bufferedReadConn{Conn: client, reader: clientBuffer.Reader}
	p.copyBidirectional(client, clientReader, clientWriter, backend, backendWriter, activity)
}

func (p *Proxy) copyBidirectional(client net.Conn, clientReader io.Reader, clientWriter io.Writer, backend net.Conn, backendWriter io.Writer, activity *tunnelActivity) {
	var wait sync.WaitGroup
	closeBoth := newCloseBoth(client, backend)

	copyOne := func(destination io.Writer, destinationConn net.Conn, source io.Reader) {
		defer wait.Done()
		// Detached goroutines are not covered by net/http's per-handler
		// recover; one panic here would otherwise kill the whole edge process.
		defer func() {
			if recovered := recover(); recovered != nil {
				p.logger.Printf("raw tunnel copy panic: %v", recovered)
				closeBoth()
			}
		}()
		err := copyStream(destination, source, activity)
		if err != nil {
			p.logger.Printf("raw tunnel copy failed: %v", err)
			closeBoth()
			return
		}
		closeWrite(destinationConn)
	}

	wait.Add(2)
	go copyOne(backendWriter, backend, clientReader)
	go copyOne(clientWriter, client, backend)
	wait.Wait()
	closeBoth()
}

func newCloseBoth(client, backend net.Conn) func() {
	var once sync.Once
	return func() {
		once.Do(func() {
			_ = client.Close()
			_ = backend.Close()
		})
	}
}

// startTunnelWatchdog closes both connections when no byte moved for the idle
// timeout, covering the replay phase as well as the bidirectional copy. The
// returned stop function is idempotent.
func (p *Proxy) startTunnelWatchdog(activity *tunnelActivity, closeBoth func()) func() {
	done := make(chan struct{})
	var wait sync.WaitGroup
	wait.Add(1)
	go func() {
		defer wait.Done()
		defer func() {
			if recovered := recover(); recovered != nil {
				p.logger.Printf("raw tunnel watchdog panic: %v", recovered)
				closeBoth()
			}
		}()
		ticker := time.NewTicker(idleCheckInterval(p.cfg.IdleTimeout))
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				if activity.idleFor() >= p.cfg.IdleTimeout {
					p.logger.Printf("raw tunnel idle timeout after %s", p.cfg.IdleTimeout)
					closeBoth()
					return
				}
			}
		}
	}()
	var once sync.Once
	return func() {
		once.Do(func() {
			close(done)
			wait.Wait()
		})
	}
}

// acquireTunnel reserves one hijack slot without blocking; over-limit callers
// get a 503 instead of queueing unbounded goroutines.
func (p *Proxy) acquireTunnel() bool {
	select {
	case p.tunnelSlots <- struct{}{}:
		p.metrics.tunnels.Add(1)
		return true
	default:
		p.metrics.rejected.Add(1)
		return false
	}
}

func (p *Proxy) releaseTunnel() {
	<-p.tunnelSlots
	p.metrics.tunnels.Add(-1)
}

func (p *Proxy) trackTunnel(conn net.Conn) {
	p.tunnelsMu.Lock()
	p.tunnels[conn] = struct{}{}
	p.tunnelsMu.Unlock()
}

func (p *Proxy) untrackTunnel(conn net.Conn) {
	p.tunnelsMu.Lock()
	delete(p.tunnels, conn)
	p.tunnelsMu.Unlock()
}

// CloseTunnels closes every active hijacked client connection and reports how
// many it closed. http.Server.Shutdown does not track hijacked connections, so
// main calls this during graceful shutdown.
func (p *Proxy) CloseTunnels() int {
	p.tunnelsMu.Lock()
	conns := make([]net.Conn, 0, len(p.tunnels))
	for conn := range p.tunnels {
		conns = append(conns, conn)
	}
	p.tunnelsMu.Unlock()
	for _, conn := range conns {
		_ = conn.Close()
	}
	return len(conns)
}

func copyStream(destination io.Writer, source io.Reader, activity *tunnelActivity) error {
	buffer := copyBufferPool.Get().([]byte)
	defer copyBufferPool.Put(buffer)
	for {
		read, readErr := source.Read(buffer)
		if read > 0 {
			activity.touch()
			written, writeErr := destination.Write(buffer[:read])
			if written > 0 {
				activity.touch()
			}
			if writeErr != nil {
				return writeErr
			}
			if written != read {
				return io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return nil
			}
			return readErr
		}
	}
}

type tunnelActivity struct {
	start time.Time
	last  atomic.Int64
}

func newTunnelActivity() *tunnelActivity {
	return &tunnelActivity{start: time.Now()}
}

func (a *tunnelActivity) touch() {
	elapsed := int64(time.Since(a.start))
	for {
		previous := a.last.Load()
		if elapsed <= previous {
			return
		}
		if a.last.CompareAndSwap(previous, elapsed) {
			return
		}
	}
}

func (a *tunnelActivity) idleFor() time.Duration {
	return time.Since(a.start) - time.Duration(a.last.Load())
}

func idleCheckInterval(idle time.Duration) time.Duration {
	interval := idle / 4
	if interval < 5*time.Millisecond {
		interval = 5 * time.Millisecond
	}
	if interval > time.Second {
		interval = time.Second
	}
	return interval
}

func closeWrite(conn net.Conn) {
	if writer, ok := conn.(interface{ CloseWrite() error }); ok {
		_ = writer.CloseWrite()
	}
}

type countingWriter struct {
	net.Conn
	counter *atomic.Uint64
}

func (w *countingWriter) Write(data []byte) (int, error) {
	written, err := w.Conn.Write(data)
	if written > 0 {
		w.counter.Add(uint64(written))
	}
	return written, err
}

type bufferedReadConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedReadConn) Read(data []byte) (int, error) {
	return c.reader.Read(data)
}

func adminAddress(admin *url.URL) string {
	if admin.Port() != "" {
		return admin.Host
	}
	return net.JoinHostPort(admin.Hostname(), "80")
}
