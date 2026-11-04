// Package probe implements the two real measurements behind the sidecar:
// exit-IP verification through a local HTTP CONNECT proxy and end-to-end
// liveness through the sing-box Clash API. It never mutates sing-box state.
package probe

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrNoExitIP is returned when every target failed inside the timeout budget.
var ErrNoExitIP = errors.New("no exit ip")

const connectHeaderLimit = 64 << 10

// ExitResult is one successful real exit-IP measurement.
type ExitResult struct {
	ExitIP string
	MS     int64
	Target string
}

// Exiter performs HTTP CONNECT + TLS + HTTP GET through a local mixed inbound.
type Exiter struct {
	// Targets defaults to DefaultTargets.
	Targets []Target
	// Dialer defaults to a zero net.Dialer.
	Dialer *net.Dialer
	// TLSConfig, when set, is cloned per connection. Tests supply a config
	// that trusts their local server; production leaves it nil.
	TLSConfig *tls.Config
}

// ExitIP tries every configured target in order within one context deadline.
// It returns the first IPv4 server response that parses as an exit IP.
func (e *Exiter) ExitIP(ctx context.Context, proxyHost string, proxyPort int, username, password string) (ExitResult, error) {
	start := time.Now()
	targets := e.Targets
	if len(targets) == 0 {
		targets = DefaultTargets
	}
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return ExitResult{}, err
		}
		body, err := e.fetch(ctx, proxyHost, proxyPort, username, password, target)
		if err != nil {
			continue
		}
		exitIP, ok := ParseExitIP(body)
		if !ok {
			continue
		}
		ms := time.Since(start).Milliseconds()
		if ms < 1 {
			ms = 1
		}
		return ExitResult{ExitIP: exitIP, MS: ms, Target: target.Host}, nil
	}
	if err := ctx.Err(); err != nil {
		return ExitResult{}, err
	}
	return ExitResult{}, ErrNoExitIP
}

func (e *Exiter) fetch(ctx context.Context, proxyHost string, proxyPort int, username, password string, target Target) ([]byte, error) {
	if target.Host == "" || target.Port < 1 || target.Port > 65535 {
		return nil, fmt.Errorf("invalid target")
	}
	dialer := e.Dialer
	if dialer == nil {
		dialer = &net.Dialer{}
	}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(proxyHost, strconv.Itoa(proxyPort)))
	if err != nil {
		return nil, fmt.Errorf("dial proxy: %w", err)
	}
	defer conn.Close()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}

	targetAddr := net.JoinHostPort(target.Host, strconv.Itoa(target.Port))
	var request strings.Builder
	fmt.Fprintf(&request, "CONNECT %s HTTP/1.1\r\n", targetAddr)
	fmt.Fprintf(&request, "Host: %s\r\n", targetAddr)
	request.WriteString("User-Agent: vpngate-probe/1\r\n")
	if username != "" || password != "" {
		credentials := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		fmt.Fprintf(&request, "Proxy-Authorization: Basic %s\r\n", credentials)
	}
	request.WriteString("\r\n")
	if _, err := io.WriteString(conn, request.String()); err != nil {
		return nil, fmt.Errorf("write connect: %w", err)
	}

	reader := bufio.NewReader(conn)
	status, err := readConnectStatus(reader)
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("connect status %d", status)
	}

	tlsConn := tls.Client(&bufferedConn{Conn: conn, reader: reader}, e.tlsConfig(target.Host))
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("tls handshake: %w", err)
	}
	defer tlsConn.Close()

	path := target.Path
	if path == "" {
		path = "/"
	}
	var getRequest strings.Builder
	fmt.Fprintf(&getRequest, "GET %s HTTP/1.1\r\n", path)
	fmt.Fprintf(&getRequest, "Host: %s\r\n", target.Host)
	getRequest.WriteString("User-Agent: vpngate-probe/1\r\n")
	getRequest.WriteString("Accept: text/plain, */*\r\n")
	getRequest.WriteString("Connection: close\r\n\r\n")
	if _, err := io.WriteString(tlsConn, getRequest.String()); err != nil {
		return nil, fmt.Errorf("write get: %w", err)
	}

	response, err := http.ReadResponse(bufio.NewReader(tlsConn), &http.Request{Method: http.MethodGet})
	if err != nil {
		return nil, fmt.Errorf("read response: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("target status %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, MaxExitBody+1))
	if err != nil {
		return nil, fmt.Errorf("read body: %w", err)
	}
	if len(body) > MaxExitBody {
		return nil, fmt.Errorf("response body exceeds %d bytes", MaxExitBody)
	}
	return body, nil
}

func (e *Exiter) tlsConfig(serverName string) *tls.Config {
	var cfg *tls.Config
	if e.TLSConfig != nil {
		cfg = e.TLSConfig.Clone()
	} else {
		cfg = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	return cfg
}

func readConnectStatus(reader *bufio.Reader) (int, error) {
	line, err := reader.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read connect status: %w", err)
	}
	size := len(line)
	fields := strings.Fields(strings.TrimSpace(line))
	if len(fields) < 2 || !strings.HasPrefix(fields[0], "HTTP/") {
		return 0, fmt.Errorf("malformed connect status line")
	}
	status, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, fmt.Errorf("malformed connect status: %w", err)
	}
	for {
		line, err = reader.ReadString('\n')
		if err != nil {
			return 0, fmt.Errorf("read connect headers: %w", err)
		}
		size += len(line)
		if size > connectHeaderLimit {
			return 0, fmt.Errorf("connect headers exceed %d bytes", connectHeaderLimit)
		}
		if line == "\r\n" || line == "\n" {
			return status, nil
		}
	}
}

// bufferedConn preserves bytes already buffered while parsing the CONNECT
// response; a plain net.Conn would drop them before the TLS handshake.
type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}
