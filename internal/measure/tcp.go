package measure

import (
	"context"
	"net"
	"strconv"
	"time"
)

// TCPLatency measures a TCP handshake in milliseconds; 0 when unreachable.
func TCPLatency(ctx context.Context, host string, port int, timeout time.Duration) int64 {
	if host == "" || port < 1 || port > 65535 {
		return 0
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	start := time.Now()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return 0
	}
	_ = conn.Close()
	ms := time.Since(start).Milliseconds()
	if ms < 1 {
		ms = 1
	}
	return ms
}
