package measure

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/probe"
	"github.com/2061969365/railway-vpngate-combined/probe/internal/singbox"
)

// FetchExitIPOptions is one exit-IP lookup through a SOCKS5 proxy.
type FetchExitIPOptions struct {
	ProxyHost string
	ProxyPort int
	Timeout   time.Duration
	TLSConfig *tls.Config
	Targets   []probe.Target
	// AllowPrivateTargets is a test/operator escape: production keeps the
	// snapshot SSRF policy on every exit-IP target.
	AllowPrivateTargets bool
	ResolveHost         singbox.HostResolver
}

// FetchExitIP tries the exit-IP echo services in order inside one shared
// budget and returns the first IPv4 response.
func FetchExitIP(ctx context.Context, opts FetchExitIPOptions) (string, *int64) {
	budget := opts.Timeout
	if budget <= 0 {
		budget = 20 * time.Second
	}
	if budget < 2*time.Second {
		budget = 2 * time.Second
	}
	targets := opts.Targets
	if len(targets) == 0 {
		targets = probe.DefaultTargets
	}
	deadline := time.Now().Add(budget)
	for _, target := range targets {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		attempt := remaining
		if attempt > 6*time.Second {
			attempt = 6 * time.Second
		}
		resolve := opts.ResolveHost
		if resolve == nil {
			resolve = singbox.LookupHost
		}
		pinned, err := singbox.ValidateRemote(target.Host, target.Port,
			opts.AllowPrivateTargets, resolve)
		if err != nil {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attempt)
		result := Socks5GetText(attemptCtx, Socks5Options{
			ProxyHost:  opts.ProxyHost,
			ProxyPort:  opts.ProxyPort,
			TargetHost: pinned.Host,
			TargetPort: pinned.Port,
			Path:       target.Path,
			Timeout:    attempt,
			SNIHost:    target.Host,
			HostHeader: target.Host,
			TLSConfig:  opts.TLSConfig,
		})
		cancel()
		if result == nil || result.Code != 200 {
			continue
		}
		exitIP, ok := probe.ParseExitIP(result.Body)
		if !ok {
			continue
		}
		ms := result.MS
		return exitIP, &ms
	}
	return "", nil
}
