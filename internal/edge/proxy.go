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

const copyBufferSize = 32 * 1024

// Proxy is the public data-plane HTTP handler.
type Proxy struct {
	cfg      Config
	logger   *log.Logger
	metrics  *Metrics
	reverse  *httputil.ReverseProxy
	adminTCP string
}

// New validates the configuration and builds the proxy handler.
func New(cfg Config, logger *log.Logger) (*Proxy, error) {
	admin, err := url.Parse(cfg.AdminURL)
	if err != nil {
		return nil, fmt.Errorf("EDGE_ADMIN %q: %w", cfg.AdminURL, err)
	}
	if admin.Scheme != "http" && admin.Scheme != "https" {
		return nil, fmt.Errorf("EDGE_ADMIN %q must use http or https", cfg.AdminURL)
	}
	if admin.Host == "" {
		return nil, fmt.Errorf("EDGE_ADMIN %q has no host", cfg.AdminURL)
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = time.Duration(DefaultDialTimeoutMS) * time.Millisecond
	}
	if cfg.IdleTimeout <= 0 {
		cfg.IdleTimeout = time.Duration(DefaultIdleTimeoutMS) * time.Millisecond
	}
	if logger == nil {
		logger = log.New(os.Stderr, "vpngate-edge: ", log.LstdFlags)
	}

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           (&net.Dialer{Timeout: cfg.DialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		MaxIdleConns:          100,
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
		cfg:      cfg,
		logger:   logger,
		metrics:  &Metrics{},
		reverse:  reverse,
		adminTCP: adminAddress(admin),
	}, nil
}

// Metrics returns the counters served on the metrics listener.
func (p *Proxy) Metrics() *Metrics {
	return p.metrics
}

// ServeHTTP routes one public request.
func (p *Proxy) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if isBodylessGet(request) {
		switch {
		case p.cfg.VLESSUUID != "" && request.URL.Path == p.cfg.DirectPath:
			p.serveRaw(writer, request, p.cfg.NodeAddr, true)
			return
		case p.cfg.VLESSUUID != "" && request.URL.Path == p.cfg.ChainPath:
			p.serveRaw(writer, request, p.cfg.ChainAddr, true)
			return
		case request.URL.Path == p.cfg.ResiPath:
			p.serveRaw(writer, request, p.adminTCP, false)
			return
		}
	}
	p.reverse.ServeHTTP(writer, request)
}

func isBodylessGet(request *http.Request) bool {
	return request.Method == http.MethodGet &&
		request.ContentLength == 0 &&
		len(request.TransferEncoding) == 0
}

// serveRaw hijacks the client connection and tunnels it to backendAddr. The
// original request is replayed with Request.Write so the backend sees the same
// headers and path; buffered bytes the HTTP server already read are forwarded
// before the bidirectional copy starts.
func (p *Proxy) serveRaw(writer http.ResponseWriter, request *http.Request, backendAddr string, count bool) {
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
	if err := request.Write(backendWriter); err != nil {
		p.logger.Printf("raw backend %s request write failed: %v", backendAddr, err)
		return
	}
	activity.touch()
	if buffered := clientBuffer.Reader.Buffered(); buffered > 0 {
		if _, err := io.CopyN(backendWriter, clientBuffer.Reader, int64(buffered)); err != nil {
			p.logger.Printf("raw backend %s buffered write failed: %v", backendAddr, err)
			return
		}
		activity.touch()
	}

	clientReader := &bufferedReadConn{Conn: client, reader: clientBuffer.Reader}
	p.copyBidirectional(client, clientReader, clientWriter, backend, backendWriter, activity)
}

func (p *Proxy) copyBidirectional(client net.Conn, clientReader io.Reader, clientWriter io.Writer, backend net.Conn, backendWriter io.Writer, activity *tunnelActivity) {
	var wait sync.WaitGroup
	var closeOnce sync.Once
	closeBoth := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = backend.Close()
		})
	}

	done := make(chan struct{})
	var watchdog sync.WaitGroup
	watchdog.Add(1)
	go func() {
		defer watchdog.Done()
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

	copyOne := func(destination io.Writer, destinationConn net.Conn, source io.Reader) {
		defer wait.Done()
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
	close(done)
	watchdog.Wait()
	closeBoth()
}

func copyStream(destination io.Writer, source io.Reader, activity *tunnelActivity) error {
	buffer := make([]byte, copyBufferSize)
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
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.CloseWrite()
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
	port := "80"
	if strings.EqualFold(admin.Scheme, "https") {
		port = "443"
	}
	return net.JoinHostPort(admin.Hostname(), port)
}
