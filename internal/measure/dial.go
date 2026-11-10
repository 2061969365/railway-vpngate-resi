package measure

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/singbox"
)

// DialOptions controls one throwaway sing-box dial.
type DialOptions struct {
	// Bin is the sing-box executable (default "sing-box").
	Bin string
	// Timeout is the total readiness budget (default 20s).
	Timeout time.Duration
	// PollInterval is the delay between readiness attempts (default 2s).
	PollInterval time.Duration
	// Gate caps concurrent temporary sing-box processes (default DefaultGate).
	Gate *Gate
	// TargetHost/Port/Path select the readiness GET (default gstatic 204).
	TargetHost string
	TargetPort int
	TargetPath string
	// TLSConfig optionally supplies extra roots for the readiness target.
	TLSConfig *tls.Config
	// AllowPrivateRemotes disables the snapshot SSRF policy for endpoint
	// remotes and the readiness target (tests / controlled local labs).
	AllowPrivateRemotes bool
	ResolveHost         singbox.HostResolver
}

// DialProbeConfig builds the throwaway single-endpoint config. The endpoint
// under test must be the only exit, otherwise the auto urltest group would
// route the measurement around it.
func DialProbeConfig(endpoint singbox.Endpoint, mixedPort int) (map[string]any, error) {
	probeEndpoint := endpoint
	probeEndpoint.Tag = "dial-probe"
	probeEndpoint.AuthRetry = "none"
	probeEndpoint.PingInterval = ""
	probeEndpoint.PingRestart = ""
	probeEndpoint.PingRestartDisabled = singbox.Bool(true)
	config, err := singbox.BuildConfig([]singbox.Endpoint{probeEndpoint}, singbox.BuildOptions{
		MixedListen: "127.0.0.1",
		MixedPort:   mixedPort,
		Final:       "auto",
	})
	if err != nil {
		return nil, err
	}
	route, ok := config["route"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("probe config has no route")
	}
	route["final"] = "dial-probe"
	return config, nil
}

const (
	freePortCooldown = 30 * time.Second
	freePortMaxTries = 64
)

var (
	freePortMu     sync.Mutex
	freePortRecent = make(map[int]time.Time)
)

// FreePort reserves and releases one loopback TCP port.
//
// Closing the listener before sing-box binds is inherently racy; the Python
// implementation serializes callers and keeps a 30s cooldown so two
// concurrent dials cannot hand out the same port. This is the same policy.
func FreePort() (int, error) {
	freePortMu.Lock()
	defer freePortMu.Unlock()
	now := time.Now()
	for index, stamp := range freePortRecent {
		if now.Sub(stamp) >= freePortCooldown {
			delete(freePortRecent, index)
		}
	}
	for attempt := 0; attempt < freePortMaxTries; attempt++ {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			return 0, err
		}
		port := listener.Addr().(*net.TCPAddr).Port
		if err := listener.Close(); err != nil {
			return 0, err
		}
		if _, recent := freePortRecent[port]; recent {
			continue
		}
		freePortRecent[port] = now
		return port, nil
	}
	return 0, fmt.Errorf("could not allocate a unique loopback port")
}

// pinEndpoint validates every remote of an endpoint and replaces the hosts
// with the literal IPs that will be dialed, so validation and connection can
// never disagree (Python _pin_endpoint).
func pinEndpoint(endpoint singbox.Endpoint, allowPrivate bool, resolve singbox.HostResolver) (singbox.Endpoint, error) {
	if resolve == nil {
		resolve = singbox.LookupHost
	}
	remotes := singbox.EndpointRemotes(endpoint)
	if len(remotes) == 0 {
		return singbox.Endpoint{}, fmt.Errorf("endpoint has no remote")
	}
	pinned := make([]singbox.Remote, 0, len(remotes))
	for _, remote := range remotes {
		item, err := singbox.ValidateRemote(remote.Host, remote.Port, allowPrivate, resolve)
		if err != nil {
			return singbox.Endpoint{}, err
		}
		pinned = append(pinned, item)
	}
	out := endpoint
	out.Server = ""
	out.ServerPort = 0
	out.Servers = nil
	if len(pinned) == 1 {
		out.Server = pinned[0].Host
		out.ServerPort = pinned[0].Port
		return out, nil
	}
	out.Servers = make([]singbox.ServerAddr, 0, len(pinned))
	for _, remote := range pinned {
		out.Servers = append(out.Servers, singbox.ServerAddr{
			Server: remote.Host, ServerPort: remote.Port, Network: "tcp",
		})
	}
	return out, nil
}

// MeasureRealLatency dials one endpoint with a throwaway sing-box and returns
// the first readiness GET's end-to-end latency.
func MeasureRealLatency(ctx context.Context, endpoint singbox.Endpoint, opts DialOptions) *int64 {
	pinned, err := pinEndpoint(endpoint, opts.AllowPrivateRemotes, opts.ResolveHost)
	if err != nil {
		return nil
	}
	_, ms := runTemporaryDial(ctx, opts, func(port int) (map[string]any, error) {
		return DialProbeConfig(pinned, port)
	}, func(attemptCtx context.Context, port int) (string, *int64) {
		targetHost := opts.TargetHost
		if targetHost == "" {
			targetHost = "www.gstatic.com"
		}
		targetPort := opts.TargetPort
		if targetPort == 0 {
			targetPort = 443
		}
		targetPath := opts.TargetPath
		if targetPath == "" {
			targetPath = "/generate_204"
		}
		resolve := opts.ResolveHost
		if resolve == nil {
			resolve = singbox.LookupHost
		}
		target, err := singbox.ValidateRemote(targetHost, targetPort,
			opts.AllowPrivateRemotes, resolve)
		if err != nil {
			return "", nil
		}
		ms := Socks5GetLatency(attemptCtx, Socks5Options{
			ProxyHost: "127.0.0.1", ProxyPort: port,
			TargetHost: target.Host, TargetPort: target.Port, Path: targetPath,
			SNIHost: targetHost, HostHeader: targetHost,
			TLSConfig: opts.TLSConfig,
		})
		return "", ms
	})
	return ms
}

// MeasureExitIP dials one endpoint with a throwaway sing-box and returns its
// real exit IP and latency.
func MeasureExitIP(ctx context.Context, endpoint singbox.Endpoint, opts DialOptions) (string, *int64) {
	pinned, err := pinEndpoint(endpoint, opts.AllowPrivateRemotes, opts.ResolveHost)
	if err != nil {
		return "", nil
	}
	return runTemporaryDial(ctx, opts, func(port int) (map[string]any, error) {
		return DialProbeConfig(pinned, port)
	}, func(attemptCtx context.Context, port int) (string, *int64) {
		return FetchExitIP(attemptCtx, FetchExitIPOptions{
			ProxyHost: "127.0.0.1", ProxyPort: port,
			TLSConfig:           opts.TLSConfig,
			AllowPrivateTargets: opts.AllowPrivateRemotes,
			ResolveHost:         opts.ResolveHost,
		})
	})
}

type temporaryProcess struct {
	port   int
	cmd    *exec.Cmd
	done   chan struct{}
	stderr *os.File
	dir    string
	gate   *Gate
}

func startTemporaryProcess(ctx context.Context, bin string, gate *Gate,
	build func(port int) (map[string]any, error)) (*temporaryProcess, error) {
	if bin == "" {
		bin = "sing-box"
	}
	if gate == nil {
		gate = DefaultGate
	}
	if err := gate.Acquire(ctx); err != nil {
		return nil, err
	}
	release := true
	defer func() {
		if release {
			gate.Release()
		}
	}()
	port, err := FreePort()
	if err != nil {
		return nil, err
	}
	config, err := build(port)
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "vpngate-dial-")
	if err != nil {
		return nil, err
	}
	removeDir := true
	defer func() {
		if removeDir {
			_ = os.RemoveAll(dir)
		}
	}()
	configPath := filepath.Join(dir, "dial.json")
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		return nil, err
	}
	stderrPath := filepath.Join(dir, "dial-stderr.log")
	stderr, err := os.OpenFile(stderrPath, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600)
	if err != nil {
		stderr = nil
	}
	cmd := exec.Command(bin, "run", "-c", configPath)
	cmd.Stdout = io.Discard
	if stderr != nil {
		cmd.Stderr = stderr
	} else {
		cmd.Stderr = io.Discard
	}
	if err := cmd.Start(); err != nil {
		if stderr != nil {
			_ = stderr.Close()
		}
		return nil, err
	}
	done := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(done)
	}()
	release = false
	removeDir = false
	return &temporaryProcess{port: port, cmd: cmd, done: done, stderr: stderr, dir: dir, gate: gate}, nil
}

func (p *temporaryProcess) Exited() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}

func (p *temporaryProcess) Stop() {
	stopProcess(p.cmd, p.done, p.stderr)
	_ = os.RemoveAll(p.dir)
	p.gate.Release()
}

func runTemporaryDial(ctx context.Context, opts DialOptions,
	build func(port int) (map[string]any, error),
	fetch func(context.Context, int) (string, *int64)) (string, *int64) {
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	pollInterval := opts.PollInterval
	if pollInterval <= 0 {
		pollInterval = 2 * time.Second
	}
	process, err := startTemporaryProcess(ctx, opts.Bin, opts.Gate, build)
	if err != nil {
		return "", nil
	}
	defer process.Stop()

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if ctx.Err() != nil {
			return "", nil
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
		exitIP, ms := fetch(attemptCtx, process.port)
		cancel()
		if exitIP != "" || ms != nil {
			return exitIP, ms
		}
		if process.Exited() {
			return "", nil
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return "", nil
		case <-process.done:
			timer.Stop()
			return "", nil
		case <-timer.C:
		}
	}
	return "", nil
}

func stopProcess(cmd *exec.Cmd, done <-chan struct{}, stderr *os.File) {
	select {
	case <-done:
	default:
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			_ = cmd.Process.Kill()
		}
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = cmd.Process.Kill()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
			}
		}
	}
	if stderr != nil {
		_ = stderr.Close()
	}
}

func sleepOrDone(ctx context.Context, done <-chan struct{}, wait time.Duration) bool {
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-done:
		return false
	case <-timer.C:
		return true
	}
}
