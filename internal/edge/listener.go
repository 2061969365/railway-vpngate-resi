package edge

import (
	"net"
	"sync"
)

// WrapListener bounds every accepted TCP connection before HTTP parsing.
// Connections above EDGE_MAX_CONNS are accepted and closed immediately, so
// the kernel backlog cannot pin the accept loop and `/healthz` recovers as
// soon as slots are released.
func (p *Proxy) WrapListener(listener net.Listener) net.Listener {
	maxConns := p.cfg.MaxConns
	if maxConns <= 0 {
		return listener
	}
	return &limitedListener{
		Listener: listener,
		slots:    make(chan struct{}, maxConns),
		metrics:  p.metrics,
	}
}

type limitedListener struct {
	net.Listener
	slots   chan struct{}
	metrics *Metrics
}

func (l *limitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		select {
		case l.slots <- struct{}{}:
			if l.metrics != nil {
				l.metrics.conns.Add(1)
			}
			return &limitedConn{Conn: conn, release: func() {
				<-l.slots
				if l.metrics != nil {
					l.metrics.conns.Add(-1)
				}
			}}, nil
		default:
			if l.metrics != nil {
				l.metrics.connRejected.Add(1)
			}
			_ = conn.Close()
		}
	}
}

type limitedConn struct {
	net.Conn
	once    sync.Once
	release func()
}

func (c *limitedConn) Close() error {
	err := c.Conn.Close()
	c.once.Do(c.release)
	return err
}

// CloseWrite delegates the TCP half-close through the wrapper. Without it the
// raw tunnel's type assertion on *net.TCPConn would silently stop half-closing
// the public side after the listener bound every connection.
func (c *limitedConn) CloseWrite() error {
	if tcp, ok := c.Conn.(*net.TCPConn); ok {
		return tcp.CloseWrite()
	}
	return nil
}
