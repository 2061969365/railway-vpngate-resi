package edge

import (
	"encoding/json"
	"net/http"
	"sync/atomic"
)

// Traffic is the public /v1/traffic snapshot. Tunnels/MaxTunnels/Rejected are
// additive fields for the hijack-tunnel bound; the manager keeps reading only
// bytes_up/bytes_down.
type Traffic struct {
	OK           bool   `json:"ok"`
	BytesUp      uint64 `json:"bytes_up"`
	BytesDown    uint64 `json:"bytes_down"`
	Connections  uint64 `json:"connections"`
	Active       int64  `json:"active"`
	Tunnels      int64  `json:"tunnels"`
	MaxTunnels   int    `json:"max_tunnels"`
	Rejected     uint64 `json:"tunnel_rejected"`
	ConnRejected uint64 `json:"conn_rejected"`
	ActiveConns  int64  `json:"active_conns"`
	MaxConns     int    `json:"max_conns"`
}

// Metrics holds the atomically updated data-plane counters.
type Metrics struct {
	bytesUp      atomic.Uint64
	bytesDown    atomic.Uint64
	connections  atomic.Uint64
	active       atomic.Int64
	tunnels      atomic.Int64
	rejected     atomic.Uint64
	connRejected atomic.Uint64
	conns        atomic.Int64
	maxTunnels   int
	maxConns     int
}

// Snapshot returns a consistent-enough point-in-time copy of the counters.
func (m *Metrics) Snapshot() Traffic {
	active := m.active.Load()
	if active < 0 {
		active = 0
	}
	tunnels := m.tunnels.Load()
	if tunnels < 0 {
		tunnels = 0
	}
	return Traffic{
		OK:           true,
		BytesUp:      m.bytesUp.Load(),
		BytesDown:    m.bytesDown.Load(),
		Connections:  m.connections.Load(),
		Active:       active,
		Tunnels:      tunnels,
		MaxTunnels:   m.maxTunnels,
		Rejected:     m.rejected.Load(),
		ConnRejected: m.connRejected.Load(),
		ActiveConns:  m.conns.Load(),
		MaxConns:     m.maxConns,
	}
}

// ServeHTTP implements the loopback metrics listener.
func (m *Metrics) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/v1/traffic":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(w).Encode(m.Snapshot())
	case "/healthz":
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("ok"))
	default:
		http.NotFound(w, r)
	}
}
