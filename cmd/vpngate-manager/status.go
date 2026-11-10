package main

import (
	"bufio"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Manager is the read-only stage 0-2 skeleton. It owns configuration and the
// status snapshot only: no refresh worker, no sing-box supervision and no
// residential data plane yet (phases 3-6).
type Manager struct {
	cfg        Config
	startedAt  time.Time
	startedISO string

	mu sync.RWMutex
}

// NewManager builds a manager with a fixed start time.
func NewManager(cfg Config) *Manager {
	started := time.Now().UTC()
	return &Manager{
		cfg:        cfg,
		startedAt:  started,
		startedISO: started.Format("2006-01-02T15:04:05Z"),
	}
}

// Ready mirrors _serving_ok: no endpoints means not ready. The skeleton never
// loads a snapshot, so /healthz stays 503 until phase 4 lands.
func (m *Manager) Ready() bool {
	return false
}

// StatusSnapshot builds the Python-compatible /api/status payload.
func (m *Manager) StatusSnapshot() map[string]any {
	now := time.Now().UTC()
	uptime := int64(now.Sub(m.startedAt).Seconds())
	if uptime < 0 {
		uptime = 0
	}
	chainMode := "config"
	if m.cfg.ClashAPIPort > 0 && m.cfg.ResiRotate {
		chainMode = "clash"
	}
	muxLimit := m.cfg.MaxMuxConnections
	resiCap := muxLimit - maxInt(1, muxLimit/5)
	if resiCap < 1 {
		resiCap = 1
	}
	resiStatus := map[string]any{"enabled": false}
	switch {
	case m.cfg.Resi != nil:
		mode := "rotation"
		if m.cfg.ResiSessionTTL > 0 && strings.Contains(m.cfg.ResiTemplate, "{session}") {
			mode = "sticky"
		}
		resiStatus = map[string]any{
			"enabled": true, "mode": mode,
			"host": maskHost(m.cfg.Resi.Server), "port": m.cfg.Resi.ServerPort,
			"path": m.cfg.ResiPath, "sticky_ttl": m.cfg.ResiSessionTTL,
			"session_age": 0, "state": "unknown",
			"exit_ip": nil, "ms": nil, "checked_at": nil, "error": nil,
			"last_probe": map[string]any{
				"state": "idle", "ips": []any{}, "distinct": 0,
				"rotating": nil, "checked_at": nil,
			},
			"mux_limit": resiCap, "throttled": 0,
		}
	case m.cfg.ResiRotate:
		resiStatus = map[string]any{
			"enabled": true, "mode": "rotate", "listen": "0.0.0.0",
			"port": m.cfg.ResiPort, "path": m.cfg.ResiPath,
			"nodes": 0, "cursor": 0, "inbounds": 0, "pool": 0, "down": 0,
			"state": "unknown", "exit_ip": nil, "ms": nil,
			"checked_at": nil, "error": nil,
			"last_probe": map[string]any{
				"state": "idle", "ips": []any{}, "distinct": 0,
				"rotating": nil, "checked_at": nil,
			},
			"mux_limit": resiCap, "throttled": 0,
		}
	}
	var vless any
	if m.cfg.VLESSUUID != "" {
		vless = map[string]any{
			"uuid":        m.cfg.VLESSUUID,
			"direct_path": "/ws-node",
			"chain_path":  "/ws-chain",
		}
	}
	chainSwitch := map[string]any{
		"mode": chainMode, "clash_port": m.cfg.ClashAPIPort,
		"ready": false, "switches": 0,
	}
	return map[string]any{
		"endpoints":       []any{},
		"countries":       []any{},
		"preferred_tag":   nil,
		"backup_tag":      nil,
		"auto_pinned":     false,
		"refresh_history": []any{},
		"refresh_ok":      0,
		"refresh_fail":    0,
		"last_refresh":    nil,
		"last_error":      nil,
		"started_at":      m.startedISO,
		"proxy":           fmt.Sprintf("127.0.0.1:%d", m.cfg.MixedPort),
		"traffic": map[string]any{
			"connections": 0, "bytes_up": 0, "bytes_down": 0,
		},
		"full_probe": map[string]any{"state": "idle", "done": 0, "total": 0},
		"refresh_job": map[string]any{
			"state": "idle", "started_at": nil, "ok": nil, "error": nil,
		},
		"probe": map[string]any{
			"state": "idle", "tag": nil, "ms": nil, "error": nil,
		},
		"verify": map[string]any{
			"state": "idle", "exit_ip": nil, "ms": nil, "via_tag": nil,
			"error": nil, "checked_at": nil,
		},
		"tunnel":       map[string]any{"state": "off"},
		"vless":        vless,
		"chain_switch": chainSwitch,
		"resi":         resiStatus,
		"pin_health": map[string]any{
			"state": "unknown", "fail_streak": 0, "checked_at": nil,
			"exit_ip": nil, "error": nil,
			"chain_switch": map[string]any{
				"mode": chainMode, "ready": false, "switches": 0,
			},
		},
		"threads":        runtime.NumGoroutine(),
		"cpu":            map[string]any{"model": cpuModel(), "cores": runtime.NumCPU(), "pct": nil},
		"memory":         map[string]any{"rss_mb": rssMB(), "pct": memPercent()},
		"uptime_seconds": uptime,
	}
}

func maxInt(left, right int) int {
	if left > right {
		return left
	}
	return right
}

// maskHost matches railway_manager._mask_host: IPv4 loses its last octet,
// IPv6 its last group; hostnames stay intact.
func maskHost(host string) string {
	if host == "" {
		return host
	}
	if strings.Contains(host, ":") {
		index := strings.LastIndex(host, ":")
		if index <= 0 {
			return host
		}
		return host[:index] + ":x"
	}
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		allDigits := true
		for _, part := range parts {
			if part == "" {
				allDigits = false
				break
			}
			for _, r := range part {
				if r < '0' || r > '9' {
					allDigits = false
					break
				}
			}
			if !allDigits {
				break
			}
		}
		if allDigits {
			return parts[0] + "." + parts[1] + "." + parts[2] + ".x"
		}
	}
	return host
}

func cpuModel() any {
	file, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return nil
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "model name") {
			_, value, found := strings.Cut(line, ":")
			if found {
				if trimmed := strings.TrimSpace(value); trimmed != "" {
					return trimmed
				}
			}
		}
	}
	return nil
}

func rssMB() any {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmRSS:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			return nil
		}
		kb, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			return nil
		}
		value := kb / 1024.0
		return float64(int(value*10+0.5)) / 10
	}
	return nil
}

func memPercent() any {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return nil
	}
	var total, available float64
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, err := strconv.ParseFloat(fields[1], 64)
		if err != nil {
			continue
		}
		switch fields[0] {
		case "MemTotal:":
			total = value
		case "MemAvailable:":
			available = value
		}
	}
	if total <= 0 {
		return nil
	}
	value := (total - available) / total * 100
	return float64(int(value*10+0.5)) / 10
}
