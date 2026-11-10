package measure

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"time"
)

// MaxResponseBody caps every measured HTTP response body (Python 65536).
const MaxResponseBody = 64 << 10

// Socks5Options is one SOCKS5 + TLS + HTTP GET measurement.
type Socks5Options struct {
	ProxyHost string
	ProxyPort int
	// TargetHost is the address sent in the SOCKS5 CONNECT. Callers that
	// validated a snapshot remote pass the pinned literal IP here.
	TargetHost string
	TargetPort int
	Path       string
	Timeout    time.Duration
	// SNIHost is the TLS server name and defaults to TargetHost. It stays the
	// original hostname when TargetHost is a pinned IP.
	SNIHost string
	// HostHeader is the HTTP Host value and defaults to TargetHost.
	HostHeader string
	// TLSConfig optionally supplies extra roots (tests). ServerName is
	// filled in when empty; certificate verification is always kept on.
	TLSConfig *tls.Config
}

// TextResult is one parsed HTTPS response through a SOCKS5 proxy.
type TextResult struct {
	Code int
	Body []byte
	MS   int64
}

// Socks5GetLatency performs one HTTPS GET and returns ms only on HTTP 204.
func Socks5GetLatency(ctx context.Context, opts Socks5Options) *int64 {
	result := Socks5GetText(ctx, opts)
	if result == nil || result.Code != http.StatusNoContent {
		return nil
	}
	ms := result.MS
	return &ms
}

// Socks5GetText performs the SOCKS5 handshake, TLS handshake and one GET.
//
// Every read shares the context deadline; the body is capped at
// MaxResponseBody. TLS verification stays enabled (no InsecureSkipVerify).
func Socks5GetText(ctx context.Context, opts Socks5Options) *TextResult {
	if opts.ProxyHost == "" || opts.ProxyPort < 1 || opts.ProxyPort > 65535 {
		return nil
	}
	if opts.TargetHost == "" || opts.TargetPort < 1 || opts.TargetPort > 65535 {
		return nil
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()

	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp",
		net.JoinHostPort(opts.ProxyHost, strconv.Itoa(opts.ProxyPort)))
	if err != nil {
		return nil
	}
	defer conn.Close()
	_ = conn.SetDeadline(deadline)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil
	}
	greeting := make([]byte, 2)
	if _, err := io.ReadFull(conn, greeting); err != nil {
		return nil
	}
	if greeting[0] != 0x05 || greeting[1] != 0x00 {
		return nil
	}
	request, err := socks5ConnectRequest(opts.TargetHost, opts.TargetPort)
	if err != nil {
		return nil
	}
	if _, err := conn.Write(request); err != nil {
		return nil
	}
	if err := readSocks5Reply(conn); err != nil {
		return nil
	}

	serverName := opts.SNIHost
	if serverName == "" {
		serverName = opts.TargetHost
	}
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.TLSConfig != nil {
		cfg = opts.TLSConfig.Clone()
	}
	cfg.InsecureSkipVerify = false
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	tlsConn := tls.Client(conn, cfg)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil
	}
	defer tlsConn.Close()

	path := opts.Path
	if path == "" {
		path = "/"
	}
	hostHeader := opts.HostHeader
	if hostHeader == "" {
		hostHeader = opts.TargetHost
	}
	start := time.Now()
	requestText := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: vpngate-measure/1\r\nConnection: close\r\n\r\n",
		path, hostHeader)
	if _, err := io.WriteString(tlsConn, requestText); err != nil {
		return nil
	}
	// Cap the whole response (headers included) at MaxResponseBody before
	// http.ReadResponse: net/textproto otherwise reads headers unbounded.
	limited := &limitedConn{Conn: tlsConn, remaining: MaxResponseBody}
	response, err := http.ReadResponse(bufio.NewReader(limited),
		&http.Request{Method: http.MethodGet})
	if err != nil {
		return nil
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBody+1))
	if err != nil {
		return nil
	}
	if len(body) > MaxResponseBody {
		return nil
	}
	ms := time.Since(start).Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return &TextResult{Code: response.StatusCode, Body: bytes.TrimSpace(body), MS: ms}
}

func socks5ConnectRequest(host string, port int) ([]byte, error) {
	request := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			request = append(request, 0x01)
			request = append(request, ip4...)
		} else if ip16 := ip.To16(); ip16 != nil {
			request = append(request, 0x04)
			request = append(request, ip16...)
		} else {
			return nil, fmt.Errorf("invalid target ip")
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("target host too long")
		}
		request = append(request, 0x03, byte(len(host)))
		request = append(request, host...)
	}
	request = append(request, byte(port>>8), byte(port))
	return request, nil
}

func readSocks5Reply(conn net.Conn) error {
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return err
	}
	if head[0] != 0x05 || head[1] != 0x00 {
		return fmt.Errorf("socks5 connect rejected")
	}
	switch head[3] {
	case 0x01:
		_, err := io.CopyN(io.Discard, conn, 6)
		return err
	case 0x03:
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return err
		}
		_, err := io.CopyN(io.Discard, conn, int64(length[0])+2)
		return err
	case 0x04:
		_, err := io.CopyN(io.Discard, conn, 18)
		return err
	default:
		return fmt.Errorf("socks5 unknown address type")
	}
}
