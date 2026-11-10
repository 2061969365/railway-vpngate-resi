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

	"github.com/2061969365/railway-vpngate-combined/probe/internal/singbox"
)

// ErrNoExitIP is returned when every target failed inside the timeout budget.
var ErrNoExitIP = errors.New("no exit ip")

// errExitResponseTooLarge is returned when headers+body exceed MaxExitBody.
var errExitResponseTooLarge = errors.New("exit response exceeds 64 KiB")

const (
	connectHeaderLimit = 64 << 10
	// connectLineLimit caps one status/header line before it is buffered.
	connectLineLimit = 8 << 10
	// defaultTargetBudget is the per-target cap. The Python caller uses
	// min(remaining, 6.0); Go keeps the same 6s ceiling so one black-holed
	// target cannot consume the whole caller budget.
	defaultTargetBudget = 6 * time.Second
)

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
	// TLSConfig, when set, is cloned per connection. It can add roots for a
	// test/local server; certificate verification is always forced on.
	TLSConfig *tls.Config
	// TargetBudget caps one target attempt. Zero uses defaultTargetBudget.
	TargetBudget time.Duration
	// AllowPrivateTargets disables the snapshot SSRF policy for targets
	// (tests/local labs). Production leaves it false.
	AllowPrivateTargets bool
	// ResolveHost overrides the DNS resolver used to pin a target hostname.
	ResolveHost singbox.HostResolver
}

// ExitIP tries every configured target in order within one context deadline.
// Each target gets its own child context with a min(remaining, 6s) budget so a
// black-holed first target cannot starve the fallbacks. It returns the first
// IPv4 server response that parses as an exit IP.
func (e *Exiter) ExitIP(ctx context.Context, proxyHost string, proxyPort int, username, password string) (ExitResult, error) {
	start := time.Now()
	targets := e.Targets
	if len(targets) == 0 {
		targets = DefaultTargets
	}
	budgetCap := e.TargetBudget
	if budgetCap <= 0 {
		budgetCap = defaultTargetBudget
	}
	deadline, hasDeadline := ctx.Deadline()
	for _, target := range targets {
		if err := ctx.Err(); err != nil {
			return ExitResult{}, err
		}
		budget := budgetCap
		if hasDeadline {
			remaining := time.Until(deadline)
			if remaining <= 0 {
				break
			}
			if remaining < budget {
				budget = remaining
			}
		}
		targetCtx, cancel := context.WithTimeout(ctx, budget)
		body, err := e.fetch(targetCtx, proxyHost, proxyPort, username, password, target)
		cancel()
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
	pinned := singbox.Remote{Host: target.Host, Port: target.Port}
	if !e.AllowPrivateTargets {
		resolve := e.ResolveHost
		if resolve == nil {
			resolve = singbox.LookupHost
		}
		var err error
		pinned, err = singbox.ValidateRemote(target.Host, target.Port, false, resolve)
		if err != nil {
			return nil, err
		}
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

	targetAddr := net.JoinHostPort(pinned.Host, strconv.Itoa(pinned.Port))
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

	reader := bufio.NewReaderSize(conn, connectLineLimit)
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

	// Cap the whole response (headers included) at MaxExitBody before
	// http.ReadResponse: net/textproto otherwise reads headers unbounded.
	limited := &limitedReadConn{Conn: tlsConn, remaining: MaxExitBody}
	response, err := http.ReadResponse(bufio.NewReader(limited), &http.Request{Method: http.MethodGet})
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
	// The public API never lets a caller disable certificate verification;
	// TLSConfig only contributes extra roots.
	cfg.InsecureSkipVerify = false
	if cfg.ServerName == "" {
		cfg.ServerName = serverName
	}
	return cfg
}

// limitedReadConn caps every byte read from the wrapped connection.
type limitedReadConn struct {
	net.Conn
	remaining int
}

func (c *limitedReadConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errExitResponseTooLarge
	}
	if len(p) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= n
	return n, err
}

func readConnectStatus(reader *bufio.Reader) (int, error) {
	line, err := readConnectLine(reader)
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
		line, err = readConnectLine(reader)
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

// readConnectLine caps each line before it is buffered. ReadString would grow
// without bound until a newline arrived, letting a local malicious proxy push
// the sidecar into OOM.
func readConnectLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadSlice('\n')
	if err != nil {
		if errors.Is(err, bufio.ErrBufferFull) {
			return "", fmt.Errorf("connect line exceeds %d bytes", connectLineLimit)
		}
		return "", err
	}
	if len(line) > connectLineLimit {
		return "", fmt.Errorf("connect line exceeds %d bytes", connectLineLimit)
	}
	return string(line), nil
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
