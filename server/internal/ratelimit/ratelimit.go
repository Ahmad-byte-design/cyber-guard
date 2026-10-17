// Package ratelimit implements the abuse controls ADR 0014 requires.
//
// CyberGuard has no authentication in v1 — see ADR 0014 for why a browser
// extension cannot hold a secret that is not extractable from its own package.
// Abuse control is therefore built entirely from rate limits and quotas, and
// the endpoint is public by construction.
//
// # Why the controls live here and not in the provider
//
// The provider's quota is finite and expensive. Spending it is the actual
// abuse, so the control that matters is per-fingerprint submission volume,
// which needs no client identity at all and so is unaffected by shared NAT
// egress — the failure mode that defeats per-IP limits.
//
// # Why in-process, and what that costs
//
// The counters used to live in Redis. Redis was removed along with the worker
// process (see ADR 0003 and docs/decisions/0013-durable-jobs-and-url-privacy.md),
// and a rate limit that requires a second datastore to be a rate limit is a
// dependency that can fail exactly when it is load-bearing.
//
// The trade this makes, stated plainly:
//
//   - Counters are per-process. Running more than one replica multiplies the
//     effective limit by the replica count. A three-replica deployment allows
//     three times the configured submission rate.
//   - Counters reset on restart, so a crash is a free reset for every subject.
//   - Neither is true of a shared counter store, and neither is acceptable
//     against a hard financial limit. If this ever needs to scale out, move the
//     counters back to a shared store and leave this interface unchanged — it is
//     deliberately shaped so that substitution is local to this package.
//
// Within a single process the behaviour is exactly as before: fixed windows,
// the same arithmetic, the same headers, the same failure semantics.
//
// # Fixed windows
//
// Fixed windows are used because they cost one in-memory increment per request
// and need no server-side session state. They permit a burst of up to 2x the
// limit across a window boundary. That is an accepted trade: the limits here
// protect a quota, not a per-user quota, and the burst is bounded by a factor of
// two rather than unbounded as it would be with no limit at all.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ErrUnavailable means the counters could not be evaluated.
//
// It is retained as an error even though an in-process counter has no dependency
// to be unavailable, because callers must be able to distinguish "the limit was
// hit" from "the limiter is broken": one is a 429 and the other is a 503. A
// future shared backend would need this path, and the interface should not have
// to change to provide it.
var ErrUnavailable = errors.New("ratelimit: counter store unavailable")

// Decision is the outcome of one limit check.
type Decision struct {
	// Allowed reports whether the request may proceed.
	Allowed bool
	// Limit is the configured ceiling, echoed in X-RateLimit-Limit.
	Limit int
	// Remaining is how many requests remain in this window. It is clamped at
	// zero: a negative value in a header invites a client to believe it has
	// credit it does not.
	Remaining int
	// Reset is when the window rolls over, echoed in X-RateLimit-Reset.
	Reset time.Time
	// RetryAfter is set only when Allowed is false.
	RetryAfter time.Duration
}

// counter is one subject's window.
type counter struct {
	count     int
	expiresAt time.Time
}

// Limiter evaluates fixed-window counters in process memory.
//
// It is safe for concurrent use. The mutex is held across the read-modify-write
// because the increment must be atomic with respect to other requests — two
// concurrent requests must not both read 59 and both be allowed as the 60th.
type Limiter struct {
	mu       sync.Mutex
	counters map[string]counter
	now      func() time.Time

	// lastSweep bounds how often expired windows are reclaimed.
	lastSweep time.Time
}

// sweepInterval is how often idle entries are dropped.
//
// Without it the map grows with every distinct subject ever seen and never
// shrinks, which is a slow leak driven entirely by hostile traffic — the one
// input guaranteed to be adversarial. Sweeping on a timer bounds memory to the
// set of subjects active within a window, not the set of subjects ever seen.
const sweepInterval = time.Minute

// New builds an in-process Limiter.
//
// now is injectable so tests can assert window arithmetic deterministically.
func New(now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{
		counters: make(map[string]counter),
		now:      now,
	}
}

// Allow consumes one unit of the named budget.
//
// scope separates independent budgets that would otherwise share a counter —
// "client" and "fingerprint", for example — so one cannot exhaust the other.
// subject identifies what is being limited; it is hashed, so a caller may pass
// a client address or a URL fingerprint without either appearing in memory
// alongside a value that a heap dump or a log could pair it with.
func (l *Limiter) Allow(ctx context.Context, scope, subject string, limit int, window time.Duration) (Decision, error) {
	// Checked before the receiver, because "no limit configured" is answerable
	// without touching any state and must never fail.
	//
	// A limit of zero means unlimited, never "reject everything": an unset
	// value should not read as a denial of service.
	if limit <= 0 {
		return Decision{Allowed: true, Limit: limit}, nil
	}
	if l == nil {
		return Decision{}, ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		// The context is how a shutting-down process stops doing work, and
		// honouring it here is what lets a request that is already gone avoid
		// consuming budget it will never be charged for.
		return Decision{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}
	if window <= 0 {
		window = time.Minute
	}

	key := keyFor(scope, subject)
	start := l.now()

	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweepLocked(start)

	entry, ok := l.counters[key]
	if !ok || !start.Before(entry.expiresAt) {
		// Either unseen, or the previous window lapsed. Starting a new window
		// here rather than extending the old one is what makes the window
		// anchored to first use: anchoring on the request would make the reset
		// time depend on request timing and never converge on a fixed interval.
		entry = counter{expiresAt: start.Add(window)}
	}
	entry.count++
	l.counters[key] = entry

	remaining := limit - entry.count
	if remaining < 0 {
		remaining = 0
	}

	decision := Decision{
		Allowed:   entry.count <= limit,
		Limit:     limit,
		Remaining: remaining,
		Reset:     entry.expiresAt.UTC(),
	}
	if !decision.Allowed {
		decision.RetryAfter = entry.expiresAt.Sub(start)
		if decision.RetryAfter < time.Second {
			// A client told to retry in 0s will hammer the endpoint, which is
			// the opposite of what a limit is for.
			decision.RetryAfter = time.Second
		}
	}
	return decision, nil
}

// sweepLocked drops lapsed windows.
//
// The caller holds the mutex. Sweeping the whole map is O(subsets) but only runs
// once per sweepInterval, and after a sweep the map holds exactly the subjects
// active in the current window. Nothing is lost by dropping an expired entry: a
// later request for that subject would have started a fresh window anyway.
func (l *Limiter) sweepLocked(now time.Time) {
	if !l.lastSweep.IsZero() && now.Sub(l.lastSweep) < sweepInterval {
		return
	}
	l.lastSweep = now

	for k, c := range l.counters {
		if !now.Before(c.expiresAt) {
			delete(l.counters, k)
		}
	}
}

// Len reports how many subjects are currently tracked. Exported for the memory
// bound to be observable in tests, which is the only way it stays true.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.counters)
}

// keyFor builds a bounded, non-identifying counter key.
//
// The subject is hashed rather than embedded. A URL fingerprint is already an
// HMAC and safe to expose, but a client address is personal data, and hashing
// both keeps the rule uniform instead of dependent on the caller's care.
func keyFor(scope, subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return scope + ":" + hex.EncodeToString(sum[:16])
}
