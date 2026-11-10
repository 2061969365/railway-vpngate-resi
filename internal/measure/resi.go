package measure

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/singbox"
)

// ResiSample is one rotation measurement (Python _resi_probe_run result).
type ResiSample struct {
	IPs      []string `json:"ips"`
	MS       []int64  `json:"ms"`
	Count    int      `json:"count"`
	Distinct int      `json:"distinct"`
	Errors   []string `json:"errors"`
	FirstMS  int64    `json:"first_ms"`
	LastMS   int64    `json:"last_ms"`
}

// ResiProbeConfig is the throwaway config whose only exit is the residential
// SOCKS5 gateway.
func ResiProbeConfig(resi singbox.ResiOutbound, port int) map[string]any {
	return map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "resi-probe-in",
			"listen": "127.0.0.1", "listen_port": port,
		}},
		"outbounds": []any{
			map[string]any{
				"type": "socks", "tag": "resi-probe",
				"server": resi.Server, "server_port": resi.ServerPort,
				"version": "5", "username": resi.Username,
				"password": resi.Password, "network": "tcp",
			},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "resi-probe"},
	}
}

// ResiRotateProbeConfig is the throwaway VLESS+WS client that measures the
// manager's own rotating third path.
func ResiRotateProbeConfig(uuid string, port int, path string, listenPort int) map[string]any {
	return map[string]any{
		"log": map[string]any{"level": "warn"},
		"inbounds": []any{map[string]any{
			"type": "mixed", "tag": "resi-rot-probe-in",
			"listen": "127.0.0.1", "listen_port": listenPort,
		}},
		"outbounds": []any{
			map[string]any{
				"type": "vless", "tag": "resi-rot-probe",
				"server": "127.0.0.1", "server_port": port, "uuid": uuid,
				"transport": map[string]any{"type": "ws", "path": path},
			},
			map[string]any{"type": "direct", "tag": "direct"},
		},
		"route": map[string]any{"final": "resi-rot-probe"},
	}
}

// pinResiOutbound pins the operator gateway to a literal IP. RESI_GATEWAY is
// operator configuration, not snapshot data, so private/loopback addresses
// stay allowed (PLAN R2-5-03); only DNS is resolved once here.
func pinResiOutbound(resi singbox.ResiOutbound) (singbox.ResiOutbound, error) {
	if resi.ServerPort < 1 || resi.ServerPort > 65535 {
		return singbox.ResiOutbound{}, fmt.Errorf("resi port %d outside 1..65535", resi.ServerPort)
	}
	host := strings.Trim(strings.TrimSpace(resi.Server), "[]")
	if host == "" {
		return singbox.ResiOutbound{}, fmt.Errorf("resi gateway is empty")
	}
	if ip := net.ParseIP(host); ip != nil {
		resi.Server = ip.String()
		return resi, nil
	}
	addresses, err := singbox.LookupHost(host)
	if err != nil || len(addresses) == 0 {
		return singbox.ResiOutbound{}, fmt.Errorf("cannot resolve resi gateway %q", host)
	}
	resi.Server = addresses[0].String()
	return resi, nil
}

// MeasureResiExitIP returns one exit IP through the residential gateway.
func MeasureResiExitIP(ctx context.Context, resi singbox.ResiOutbound, bin string,
	timeout, pollInterval time.Duration) (string, *int64) {
	sample := MeasureResiRotation(ctx, resi, 1, bin, timeout, pollInterval)
	if sample == nil || len(sample.IPs) == 0 {
		return "", nil
	}
	ms := sample.FirstMS
	return sample.IPs[0], &ms
}

// MeasureResiRotation collects up to count sequential exit IPs through the
// gateway. Every sample opens a fresh connection so the gateway rotates.
func MeasureResiRotation(ctx context.Context, resi singbox.ResiOutbound, count int,
	bin string, timeout, pollInterval time.Duration) *ResiSample {
	if count < 1 {
		count = 1
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	pinned, err := pinResiOutbound(resi)
	if err != nil {
		return nil
	}
	resi = pinned
	acquireCtx, cancelAcquire := context.WithTimeout(ctx, 30*time.Second)
	process, err := startTemporaryProcess(acquireCtx, bin, DefaultGate,
		func(port int) (map[string]any, error) {
			return ResiProbeConfig(resi, port), nil
		})
	cancelAcquire()
	if err != nil {
		return nil
	}
	defer process.Stop()

	deadline := time.Now().Add(timeout)
	ips := make([]string, 0, count)
	stamps := make([]int64, 0, count)
	errorsList := make([]string, 0, 2)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return nil
		}
		remaining := time.Until(deadline)
		attempt := remaining
		if attempt > 10*time.Second {
			attempt = 10 * time.Second
		}
		if attempt < time.Second {
			attempt = time.Second
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attempt)
		exitIP, ms := FetchExitIP(attemptCtx, FetchExitIPOptions{
			ProxyHost: "127.0.0.1", ProxyPort: process.port,
		})
		cancel()
		if exitIP != "" && ms != nil {
			ips = append(ips, exitIP)
			stamps = append(stamps, *ms)
			break
		}
		if process.Exited() {
			errorsList = append(errorsList, "probe sing-box exited")
			break
		}
		if !sleepOrDone(ctx, process.done, pollInterval) {
			break
		}
	}

	totalDeadline := deadline.Add(time.Duration(count-1) * 15 * time.Second)
	// Python keeps the second loop guarded by ``ips``: when the first sample
	// never arrives, return at the caller budget instead of adding 15s per
	// extra requested IP.
	for len(ips) > 0 && len(ips) < count && time.Now().Before(totalDeadline) {
		if ctx.Err() != nil {
			break
		}
		remaining := time.Until(totalDeadline)
		attempt := remaining
		if attempt > 15*time.Second {
			attempt = 15 * time.Second
		}
		if attempt < time.Second {
			attempt = time.Second
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attempt)
		exitIP, ms := FetchExitIP(attemptCtx, FetchExitIPOptions{
			ProxyHost: "127.0.0.1", ProxyPort: process.port,
		})
		cancel()
		if exitIP != "" && ms != nil {
			ips = append(ips, exitIP)
			stamps = append(stamps, *ms)
			continue
		}
		errorsList = append(errorsList, "no exit ip")
		break
	}
	if len(ips) == 0 {
		return nil
	}
	return newResiSample(ips, stamps, errorsList)
}

// MeasureResiRotate samples the rotating third path. Dead nodes in the pool
// are walked past instead of aborting the whole measurement.
func MeasureResiRotate(ctx context.Context, uuid string, port int, path string,
	count int, bin string, timeout, pollInterval time.Duration) *ResiSample {
	if count < 1 {
		count = 1
	}
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	acquireCtx, cancelAcquire := context.WithTimeout(ctx, 30*time.Second)
	process, err := startTemporaryProcess(acquireCtx, bin, DefaultGate,
		func(listenPort int) (map[string]any, error) {
			return ResiRotateProbeConfig(uuid, port, path, listenPort), nil
		})
	cancelAcquire()
	if err != nil {
		return nil
	}
	defer process.Stop()

	deadline := time.Now().Add(timeout)
	ips := make([]string, 0, count)
	stamps := make([]int64, 0, count)
	errorsList := make([]string, 0, count)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return nil
		}
		remaining := time.Until(deadline)
		attempt := remaining
		if attempt > 10*time.Second {
			attempt = 10 * time.Second
		}
		if attempt < time.Second {
			attempt = time.Second
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attempt)
		exitIP, ms := FetchExitIP(attemptCtx, FetchExitIPOptions{
			ProxyHost: "127.0.0.1", ProxyPort: process.port,
		})
		cancel()
		if exitIP != "" && ms != nil {
			ips = append(ips, exitIP)
			stamps = append(stamps, *ms)
			break
		}
		if process.Exited() {
			errorsList = append(errorsList, "probe sing-box exited")
			break
		}
		if !sleepOrDone(ctx, process.done, pollInterval) {
			break
		}
	}

	totalDeadline := deadline.Add(time.Duration(count) * 15 * time.Second)
	maxAttempts := count * 4
	if maxAttempts < 1 {
		maxAttempts = 1
	}
	attempts := 0
	for len(ips) < count && attempts < maxAttempts && time.Now().Before(totalDeadline) {
		if ctx.Err() != nil {
			break
		}
		attempts++
		remaining := time.Until(totalDeadline)
		attempt := remaining
		if attempt > 15*time.Second {
			attempt = 15 * time.Second
		}
		if attempt < time.Second {
			attempt = time.Second
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attempt)
		exitIP, ms := FetchExitIP(attemptCtx, FetchExitIPOptions{
			ProxyHost: "127.0.0.1", ProxyPort: process.port,
		})
		cancel()
		if exitIP != "" && ms != nil {
			ips = append(ips, exitIP)
			stamps = append(stamps, *ms)
			continue
		}
		errorsList = append(errorsList, "no exit ip")
	}
	if len(ips) == 0 {
		return nil
	}
	return newResiSample(ips, stamps, errorsList)
}

func newResiSample(ips []string, stamps []int64, errorsList []string) *ResiSample {
	distinct := make(map[string]struct{}, len(ips))
	for _, ip := range ips {
		distinct[ip] = struct{}{}
	}
	first, last := int64(0), int64(0)
	if len(stamps) > 0 {
		first = stamps[0]
		last = stamps[len(stamps)-1]
	}
	return &ResiSample{
		IPs: ips, MS: stamps, Count: len(ips), Distinct: len(distinct),
		Errors: errorsList, FirstMS: first, LastMS: last,
	}
}
