package measure

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/2061969365/railway-vpngate-combined/probe/internal/probe"
)

// MixedOptions is one exit-IP measurement through a local sing-box mixed
// inbound (HTTP CONNECT + proxy auth + TLS).
type MixedOptions struct {
	ProxyHost           string
	ProxyPort           int
	Username            string
	Password            string
	Timeout             time.Duration
	TLSConfig           *tls.Config
	Targets             []probe.Target
	AllowPrivateTargets bool
}

// MeasureMixedExitIP reuses probe.Exiter for the CONNECT/TLS/parse work and
// walks the exit-IP targets inside one total budget (<=6s each), matching
// measure_mixed_exit_ip.
func MeasureMixedExitIP(ctx context.Context, opts MixedOptions) (string, *int64) {
	budget := opts.Timeout
	if budget <= 0 {
		budget = 8 * time.Second
	}
	if budget < 50*time.Millisecond {
		budget = 50 * time.Millisecond
	}
	targets := opts.Targets
	if len(targets) == 0 {
		targets = probe.DefaultTargets
	}
	deadline := time.Now().Add(budget)
	exiter := &probe.Exiter{
		TLSConfig:           opts.TLSConfig,
		AllowPrivateTargets: opts.AllowPrivateTargets,
	}
	for _, target := range targets {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			break
		}
		attempt := remaining
		if attempt > 6*time.Second {
			attempt = 6 * time.Second
		}
		attemptCtx, cancel := context.WithTimeout(ctx, attempt)
		exiter.Targets = []probe.Target{target}
		result, err := exiter.ExitIP(attemptCtx, opts.ProxyHost, opts.ProxyPort,
			opts.Username, opts.Password)
		cancel()
		if err != nil {
			continue
		}
		ms := result.MS
		return result.ExitIP, &ms
	}
	return "", nil
}
