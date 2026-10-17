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
// # Fail closed
//
// If Redis is unreachable the counters cannot be evaluated, and a submission
// that proceeds unguarded would spend real quota. Every method here therefore
// returns an error rather than a permissive result, and the caller rejects the
// request. Silently allowing traffic when the limiter is broken would turn a
// visible, recoverable outage into an invisible, unbounded bill.
//
// # Fixed windows
//
// Fixed windows are used because they cost one INCR per request and need no
// server-side session state. They permit a burst of up to 2x the limit across a
// window boundary. That is an accepted trade: the limits here protect a quota,
// not a per-user quota, and the burst is bounded by a factor of two rather
// than unbounded as it would be with no limit at all.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

// keyPrefix namespaces counters so a shared Redis cannot collide, and so the
// whole namespace can be deleted in one command during an incident.
const keyPrefix = "cyberguard:ratelimit:"

// ErrUnavailable means the counters could not be evaluated.
//
// It is deliberately not wrapped from the Redis client directly: callers need
// to distinguish "the limit was hit" from "the limiter is broken", because one
// is a 429 and the other is a 503.
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

// Limiter evaluates fixed-window counters in Redis.
type Limiter struct {
	rdb redis.UniversalClient
	now func() time.Time
}

// New builds a Limiter over an existing Redis client.
//
// now is injectable so tests can assert window arithmetic deterministically.
func New(rdb redis.UniversalClient, now func() time.Time) *Limiter {
	if now == nil {
		now = time.Now
	}
	return &Limiter{rdb: rdb, now: now}
}

// Allow consumes one unit of the named budget.
//
// scope separates independent budgets that would otherwise share a counter —
// "client" and "fingerprint", for example — so one cannot exhaust the other.
// subject identifies what is being limited; it is hashed, so a caller may pass
// a client address or a URL fingerprint without either appearing in a Redis
// key listing.
func (l *Limiter) Allow(ctx context.Context, scope, subject string, limit int, window time.Duration) (Decision, error) {
	// Checked before the client, because "no limit configured" is answerable
	// without Redis and must not fail when Redis happens to be down.
	//
	// A limit of zero means unlimited, never "reject everything": an unset
	// value should not read as a denial of service.
	if limit <= 0 {
		return Decision{Allowed: true, Limit: limit}, nil
	}
	if l == nil || l.rdb == nil {
		return Decision{}, ErrUnavailable
	}
	if window <= 0 {
		window = time.Minute
	}

	key := keyFor(scope, subject)
	start := l.now()

	values, err := incrementScript.Run(ctx, l.rdb, []string{key}, window.Milliseconds()).Result()
	if err != nil {
		return Decision{}, fmt.Errorf("%w: %w", ErrUnavailable, err)
	}

	parts, ok := values.([]any)
	if !ok || len(parts) != 2 {
		return Decision{}, fmt.Errorf("%w: unexpected script result", ErrUnavailable)
	}

	count, ok := parts[0].(int64)
	if !ok {
		return Decision{}, fmt.Errorf("%w: unexpected counter value", ErrUnavailable)
	}
	ttlMS, ok := parts[1].(int64)
	if !ok {
		return Decision{}, fmt.Errorf("%w: unexpected ttl value", ErrUnavailable)
	}

	remaining := limit - int(count)
	if remaining < 0 {
		remaining = 0
	}

	// The window rolls over relative to when this counter was created, not to
	// when the request arrived. Anchoring on the request would make the reset
	// time depend on request timing and never converge on the TTL.
	reset := start.Add(time.Duration(ttlMS) * time.Millisecond)

	decision := Decision{
		Allowed:   int(count) <= limit,
		Limit:     limit,
		Remaining: remaining,
		Reset:     reset.UTC(),
	}
	if !decision.Allowed {
		decision.RetryAfter = reset.Sub(start)
		if decision.RetryAfter < time.Second {
			// A client told to retry in 0s will hammer the endpoint, which is
			// the opposite of what a limit is for.
			decision.RetryAfter = time.Second
		}
	}
	return decision, nil
}

// incrementScript increments a counter and sets its expiry on first use.
//
// INCR and PEXPIRE are separate commands, so without a script a crash between
// them would leave a counter with no TTL — a permanent, un-recoverable denial
// of that subject until someone noticed and deleted it.
//
// The script also returns the remaining TTL so the caller can compute an exact
// reset instant without a second round trip.
var incrementScript = redis.NewScript(`
local count = redis.call('INCR', KEYS[1])
if count == 1 then
  redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
return {count, ttl}
`)

// keyFor builds a bounded, non-identifying counter key.
//
// The subject is hashed rather than embedded. A URL fingerprint is already an
// HMAC and safe to expose, but a client address is personal data that should
// not sit in a Redis key listing readable by anyone with redis-cli, and hashing
// both keeps the rule uniform instead of dependent on the caller's care.
func keyFor(scope, subject string) string {
	sum := sha256.Sum256([]byte(subject))
	return keyPrefix + scope + ":" + hex.EncodeToString(sum[:16])
}
