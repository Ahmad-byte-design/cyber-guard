package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"
)

// The limiter is in-process, so there is no live server to test against: every
// behaviour is reachable from this file. The properties that matter are the
// window arithmetic, the fail-closed contract, the concurrency guarantee, and
// the memory bound.

// A nil limiter must fail closed, not allow everything.
//
// This is the property that stood in for "Redis is down". An in-process counter
// cannot be unreachable, but a nil Limiter is still expressible — a caller that
// forgot to build one — and treating that as permission would be the exact
// failure the old dependency-failure path was built to prevent.
func TestNilLimiterFailsClosed(t *testing.T) {
	t.Parallel()

	var l *Limiter
	if _, err := l.Allow(t.Context(), "client", "1.2.3.4", 10, time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Allow on a nil limiter = %v, want ErrUnavailable", err)
	}
}

// A cancelled context is reported rather than treated as permission. A request
// that has already been abandoned must not consume budget, and a shutting-down
// process must stop doing work.
func TestCancelledContextIsReportedNotPermitted(t *testing.T) {
	t.Parallel()

	l := New(time.Now)
	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if _, err := l.Allow(ctx, "client", "1.2.3.4", 10, time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Allow with a cancelled context = %v, want ErrUnavailable", err)
	}
}

// A limit of zero means "not configured", not "reject everything". Rejecting
// every request would be a far more damaging reading of an unset value.
func TestZeroLimitMeansUnlimited(t *testing.T) {
	t.Parallel()

	// A zero-valued limiter with no maps: if the limit check did not
	// short-circuit, this would panic or fail closed rather than allow.
	l := &Limiter{}
	decision, err := l.Allow(t.Context(), "client", "1.2.3.4", 0, time.Minute)
	if err != nil {
		t.Fatalf("Allow with limit 0 = %v, want no error", err)
	}
	if !decision.Allowed {
		t.Error("a zero limit rejected the request; it should mean unlimited")
	}
}

// The window admits exactly the limit, then refuses, and the counter resets when
// the window lapses. This is the whole behaviour the headers describe.
func TestWindowAdmitsTheLimitThenResets(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	l := New(func() time.Time { return now })

	for i := 1; i <= 3; i++ {
		d, err := l.Allow(t.Context(), "client", "1.2.3.4", 3, time.Minute)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		if !d.Allowed {
			t.Fatalf("request %d was refused, want allowed", i)
		}
		if want := 3 - i; d.Remaining != want {
			t.Errorf("request %d: Remaining = %d, want %d", i, d.Remaining, want)
		}
	}

	refused, err := l.Allow(t.Context(), "client", "1.2.3.4", 3, time.Minute)
	if err != nil {
		t.Fatalf("over-limit request: %v", err)
	}
	if refused.Allowed {
		t.Fatal("the fourth request was allowed with a limit of 3")
	}
	if refused.Remaining != 0 {
		t.Errorf("Remaining = %d on a refusal, want 0 rather than a negative credit", refused.Remaining)
	}
	if refused.RetryAfter < time.Second {
		t.Errorf("RetryAfter = %s, want at least 1s so a client does not hammer", refused.RetryAfter)
	}

	// One second before the window lapses the counter still holds.
	now = now.Add(59 * time.Second)
	if d, _ := l.Allow(t.Context(), "client", "1.2.3.4", 3, time.Minute); d.Allowed {
		t.Error("the window reset early")
	}

	// At the window boundary it does not.
	now = now.Add(time.Second)
	d, err := l.Allow(t.Context(), "client", "1.2.3.4", 3, time.Minute)
	if err != nil {
		t.Fatalf("first request of the new window: %v", err)
	}
	if !d.Allowed {
		t.Error("the new window did not admit its first request")
	}
}

// The window is anchored to the first request in it, not to the wall clock, so
// the advertised reset time is exact and does not drift with request timing.
func TestWindowIsAnchoredToFirstUse(t *testing.T) {
	t.Parallel()

	start := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	now := start
	l := New(func() time.Time { return now })

	if _, err := l.Allow(t.Context(), "client", "1.2.3.4", 5, 90*time.Second); err != nil {
		t.Fatalf("Allow: %v", err)
	}

	// A minute of requests later, the reset must still be 90s from the *first*
	// one, not from now.
	now = start.Add(time.Minute)
	d, err := l.Allow(t.Context(), "client", "1.2.3.4", 5, 90*time.Second)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if want := start.Add(90 * time.Second); !d.Reset.Equal(want) {
		t.Errorf("Reset = %s, want %s", d.Reset, want)
	}
}

// Counter keys must not contain the subject: a client address is personal data,
// and an in-memory map is just as inspectable as a key listing.
func TestCounterKeysAreHashed(t *testing.T) {
	t.Parallel()

	key := keyFor("client", "203.0.113.7")
	if strings.Contains(key, "203.0.113.7") {
		t.Errorf("counter key %q contains the raw subject", key)
	}
	if !strings.HasPrefix(key, "client:") {
		t.Errorf("counter key %q is not scoped", key)
	}
}

func TestCounterKeysAreBounded(t *testing.T) {
	t.Parallel()

	// A long subject must not produce a long key: an unbounded key in an
	// unbounded map is a way to consume memory.
	key := keyFor("fingerprint", strings.Repeat("a", 4096))
	if len(key) > 128 {
		t.Errorf("counter key is %d characters for a 4 KiB subject", len(key))
	}
}

// Different subjects and different scopes must not share a counter.
func TestCounterKeysAreDistinct(t *testing.T) {
	t.Parallel()

	seen := map[string]string{}
	for _, k := range []struct{ scope, subject string }{
		{"client", "1.2.3.4"},
		{"client", "1.2.3.5"},
		{"fingerprint", "1.2.3.4"},
	} {
		key := keyFor(k.scope, k.subject)
		if prev, dup := seen[key]; dup {
			t.Errorf("%s/%s collides with %s", k.scope, k.subject, prev)
		}
		seen[key] = k.scope + "/" + k.subject
	}
}

// Two scopes for the same subject must not exhaust one another: a client that
// spent its fingerprint budget must still be able to read, and vice versa.
func TestScopesDoNotShareACounter(t *testing.T) {
	t.Parallel()

	l := New(time.Now)
	for range 2 {
		if d, _ := l.Allow(t.Context(), "fingerprint", "abc", 2, time.Minute); !d.Allowed {
			t.Fatal("fingerprint budget refused early")
		}
	}
	if d, _ := l.Allow(t.Context(), "fingerprint", "abc", 2, time.Minute); d.Allowed {
		t.Error("fingerprint budget was not exhausted")
	}
	if d, _ := l.Allow(t.Context(), "client", "abc", 2, time.Minute); !d.Allowed {
		t.Error("exhausting the fingerprint budget also exhausted the client budget")
	}
}

// The increment must be atomic with respect to other requests. Without the lock
// spanning the read-modify-write, concurrent requests could each read the same
// count and all be admitted past the limit — which is the one bug a rate limiter
// cannot have.
func TestConcurrentRequestsNeverExceedTheLimit(t *testing.T) {
	t.Parallel()

	const limit = 50
	const callers = 400

	l := New(time.Now)
	var wg sync.WaitGroup
	allowed := make(chan bool, callers)

	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := l.Allow(context.Background(), "client", "1.2.3.4", limit, time.Minute)
			if err != nil {
				t.Errorf("Allow: %v", err)
				return
			}
			allowed <- d.Allowed
		}()
	}
	wg.Wait()
	close(allowed)

	got := 0
	for a := range allowed {
		if a {
			got++
		}
	}
	if got != limit {
		t.Errorf("%d requests were allowed, want exactly %d", got, limit)
	}
}

// Memory is bounded by the subjects active in the current window, not by the
// subjects ever seen. Without this, hostile traffic that never repeats a subject
// would grow the map without limit — and hostile traffic is the one input
// guaranteed to arrive.
func TestExpiredWindowsAreReclaimed(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	l := New(func() time.Time { return now })

	for i := range 500 {
		if _, err := l.Allow(t.Context(), "client", fmt.Sprintf("10.0.0.%d", i), 10, time.Minute); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	if got := l.Len(); got != 500 {
		t.Fatalf("Len = %d, want 500 subjects tracked", got)
	}

	// Past the sweep interval and past every window.
	now = now.Add(sweepInterval + time.Minute)
	if _, err := l.Allow(t.Context(), "client", "10.0.1.1", 10, time.Minute); err != nil {
		t.Fatalf("Allow after sweep: %v", err)
	}
	if got := l.Len(); got != 1 {
		t.Errorf("Len = %d after all windows lapsed, want only the new subject", got)
	}
}

// A reclaimed window must behave exactly like a first request: the subject is
// not penalised for having existed in an earlier window.
func TestReclaimedWindowStartsFromZero(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	l := New(func() time.Time { return now })

	for range 5 {
		if d, _ := l.Allow(t.Context(), "fingerprint", "abc", 5, time.Minute); !d.Allowed {
			t.Fatal("refused inside the window")
		}
	}
	if d, _ := l.Allow(t.Context(), "fingerprint", "abc", 5, time.Minute); d.Allowed {
		t.Fatal("the window did not exhaust")
	}

	now = now.Add(sweepInterval + time.Minute)
	d, err := l.Allow(t.Context(), "fingerprint", "abc", 5, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !d.Allowed || d.Remaining != 4 {
		t.Errorf("first request of a new window = (allowed %v, remaining %d), want (true, 4)", d.Allowed, d.Remaining)
	}
}
