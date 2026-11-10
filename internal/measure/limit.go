package measure

import (
	"errors"
	"net"
)

// errResponseTooLarge is returned once a measured HTTP response exceeds the
// shared 64 KiB budget (headers plus body, matching Python's raw cap).
var errResponseTooLarge = errors.New("measure response exceeds 64 KiB")

// limitedConn caps every byte read from the wrapped connection.
type limitedConn struct {
	net.Conn
	remaining int64
}

func (c *limitedConn) Read(p []byte) (int, error) {
	if c.remaining <= 0 {
		return 0, errResponseTooLarge
	}
	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.Conn.Read(p)
	c.remaining -= int64(n)
	return n, err
}
