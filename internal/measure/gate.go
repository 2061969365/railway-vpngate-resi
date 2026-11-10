package measure

import (
	"context"
	"time"
)

// MaxConcurrentDials caps throwaway sing-box processes (Python
// MAX_CONCURRENT_DIALS). Excess dialers queue instead of OOMing a 1 GB box.
const MaxConcurrentDials = 10

// DefaultAcquireTimeout is Python's _DIAL_GATE.acquire(timeout=30) bound.
const DefaultAcquireTimeout = 30 * time.Second

// Gate is a counting semaphore for temporary sing-box dials.
type Gate struct {
	slots chan struct{}
	// Timeout caps one Acquire wait; zero uses DefaultAcquireTimeout.
	Timeout time.Duration
}

// NewGate builds a gate with the given capacity (<=0 means 1).
func NewGate(capacity int) *Gate {
	if capacity <= 0 {
		capacity = 1
	}
	return &Gate{slots: make(chan struct{}, capacity), Timeout: DefaultAcquireTimeout}
}

// DefaultGate is the process-wide dial gate.
var DefaultGate = NewGate(MaxConcurrentDials)

// Acquire blocks until a slot is free, ctx is done, or the gate's timeout
// expires (default 30s, matching Python's dial gate).
func (g *Gate) Acquire(ctx context.Context) error {
	if g == nil {
		return nil
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	timeout := g.Timeout
	if timeout <= 0 {
		timeout = DefaultAcquireTimeout
	}
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= timeout {
		select {
		case g.slots <- struct{}{}:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	acquireCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	select {
	case g.slots <- struct{}{}:
		return nil
	case <-acquireCtx.Done():
		return acquireCtx.Err()
	}
}

// TryAcquire waits at most timeout for a slot.
func (g *Gate) TryAcquire(timeout time.Duration) bool {
	if g == nil {
		return true
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case g.slots <- struct{}{}:
		return true
	case <-timer.C:
		return false
	}
}

// Release frees a slot. It must be called once per successful acquire.
func (g *Gate) Release() {
	if g == nil {
		return
	}
	select {
	case <-g.slots:
	default:
	}
}
