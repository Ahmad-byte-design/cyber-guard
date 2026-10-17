//go:build integration

package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Limiter behaviour against a live Redis:
//
//	docker compose up -d redis
//	docker compose run --rm go go test -tags integration ./internal/ratelimit/...

func integrationLimiter(t *testing.T, now func() time.Time) (*Limiter, *redis.Client) {
	t.Helper()

	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "redis:6379"
	}

	// A separate logical database from the running application: these tests
	// delete every counter they own, and sharing a database with a live API
	// would mean clearing its rate-limit state mid-run.
	rdb := redis.NewClient(&redis.Options{Addr: addr, DB: testRedisDB_LIMIT()})
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis at %s is not reachable: %v", addr, err)
	}

	t.Cleanup(func() { _ = rdb.Close() })
	if now == nil {
		now = time.Now
	}
	return New(rdb, now), rdb
}

func flush(t *testing.T, rdb *redis.Client) {
	t.Helper()
	keys, err := rdb.Keys(t.Context(), keyPrefix+"*").Result()
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	if len(keys) > 0 {
		if err := rdb.Del(t.Context(), keys...).Err(); err != nil {
			t.Fatalf("del: %v", err)
		}
	}
}

// Requests up to the limit are allowed; the next one is refused.
func TestLimitIsEnforced(t *testing.T) {
	l, rdb := integrationLimiter(t, nil)
	flush(t, rdb)

	const limit = 5
	for i := range limit {
		d, err := l.Allow(t.Context(), "client", "203.0.113.7", limit, time.Minute)
		if err != nil {
			t.Fatalf("Allow %d: %v", i, err)
		}
		if !d.Allowed {
			t.Fatalf("request %d was refused below the limit", i)
		}
		if want := limit - i - 1; d.Remaining != want {
			t.Errorf("remaining = %d, want %d", d.Remaining, want)
		}
	}

	d, err := l.Allow(t.Context(), "client", "203.0.113.7", limit, time.Minute)
	if err != nil {
		t.Fatalf("Allow over the limit: %v", err)
	}
	if d.Allowed {
		t.Error("a request past the limit was allowed")
	}
	if d.Remaining != 0 {
		t.Errorf("remaining = %d, want 0; a negative value would imply credit", d.Remaining)
	}
	if d.RetryAfter <= 0 {
		t.Error("a refused request carries no Retry-After")
	}
}

// A refused client is told to wait at least a second, so it cannot hammer the
// endpoint in a tight loop.
func TestRetryAfterHasAFloor(t *testing.T) {
	l, rdb := integrationLimiter(t, nil)
	flush(t, rdb)

	for range 2 {
		if _, err := l.Allow(t.Context(), "client", "203.0.113.9", 1, time.Minute); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	d, err := l.Allow(t.Context(), "client", "203.0.113.9", 1, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if d.Allowed {
		t.Fatal("the request was allowed past a limit of 1")
	}
	if d.RetryAfter < time.Second {
		t.Errorf("RetryAfter = %s, want at least 1s", d.RetryAfter)
	}
}

// The reset time is derived from the window, not from when the request arrived,
// so it stays meaningful across requests.
func TestResetTracksTheWindow(t *testing.T) {
	fixed := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	l, rdb := integrationLimiter(t, func() time.Time { return fixed })
	flush(t, rdb)

	d, err := l.Allow(t.Context(), "client", "198.51.100.1", 10, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if !d.Allowed {
		t.Fatal("the first request was refused")
	}
	if d.Reset.Before(fixed) {
		t.Errorf("reset %s is before the request time %s", d.Reset, fixed)
	}
	if d.Reset.After(fixed.Add(time.Minute + time.Second)) {
		t.Errorf("reset %s is beyond the window end", d.Reset)
	}
}

// A counter expires, so an abandoned key does not consume memory forever and a
// client is not locked out permanently by a stale burst.
func TestCounterExpires(t *testing.T) {
	l, rdb := integrationLimiter(t, nil)
	flush(t, rdb)

	if _, err := l.Allow(t.Context(), "client", "192.0.2.44", 1, 400*time.Millisecond); err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if d, _ := l.Allow(t.Context(), "client", "192.0.2.44", 1, 400*time.Millisecond); d.Allowed {
		t.Fatal("the limit was not enforced inside the window")
	}

	// A counter with no TTL would deny this client forever.
	ttl, err := rdb.PTTL(t.Context(), keyFor("client", "192.0.2.44")).Result()
	if err != nil {
		t.Fatalf("PTTL: %v", err)
	}
	if ttl <= 0 || ttl > 500*time.Millisecond {
		t.Fatalf("counter TTL = %s, want a positive value inside the window", ttl)
	}

	time.Sleep(500 * time.Millisecond)
	if d, _ := l.Allow(t.Context(), "client", "192.0.2.44", 1, 400*time.Millisecond); !d.Allowed {
		t.Error("the client is still limited after the window expired")
	}
}

// Different subjects have independent budgets.
func TestSubjectsHaveIndependentBudgets(t *testing.T) {
	l, rdb := integrationLimiter(t, nil)
	flush(t, rdb)

	for range 2 {
		if _, err := l.Allow(t.Context(), "client", "203.0.113.1", 1, time.Minute); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	if d, _ := l.Allow(t.Context(), "client", "203.0.113.1", 1, time.Minute); d.Allowed {
		t.Error("the first subject is not limited")
	}
	if d, _ := l.Allow(t.Context(), "client", "203.0.113.2", 1, time.Minute); !d.Allowed {
		t.Error("a second subject shares the first subject's budget")
	}
}

// Different scopes have independent budgets, so a client cannot exhaust the
// per-fingerprint quota through the per-client counter or the reverse.
func TestScopesHaveIndependentBudgets(t *testing.T) {
	l, rdb := integrationLimiter(t, nil)
	flush(t, rdb)

	for range 2 {
		if _, err := l.Allow(t.Context(), "client", "same-subject", 1, time.Minute); err != nil {
			t.Fatalf("Allow: %v", err)
		}
	}
	if d, _ := l.Allow(t.Context(), "client", "same-subject", 1, time.Minute); d.Allowed {
		t.Error("the client scope is not limited")
	}
	if d, _ := l.Allow(t.Context(), "fingerprint", "same-subject", 1, time.Minute); !d.Allowed {
		t.Error("the fingerprint scope is limited by the client scope")
	}
}

// Concurrency must not overshoot the limit: the INCR-and-EXPIRE pair runs as
// one script precisely so a race cannot create an unbounded counter.
func TestConcurrentRequestsDoNotOvershoot(t *testing.T) {
	l, rdb := integrationLimiter(t, nil)
	flush(t, rdb)

	const limit = 20
	const attempts = 100

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		allowed int
	)

	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := l.Allow(t.Context(), "client", "203.0.113.77", limit, time.Minute)
			if err != nil {
				t.Errorf("Allow: %v", err)
				return
			}
			if d.Allowed {
				mu.Lock()
				allowed++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if allowed > limit {
		t.Errorf("%d requests were allowed with a limit of %d", allowed, limit)
	}
	if allowed < 1 {
		t.Error("no request was allowed at all")
	}
}

// A Redis outage fails closed. This is the property that protects the provider
// quota: if the counters cannot be read, requests stop rather than proceed
// unguarded.
func TestRedisOutageFailsClosed(t *testing.T) {
	_, rdb := integrationLimiter(t, nil)
	_ = rdb.Close()

	l := New(rdb, time.Now)
	_, err := l.Allow(t.Context(), "client", "203.0.113.5", 10, time.Minute)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Allow with Redis closed = %v, want ErrUnavailable", err)
	}
}

// The whole set of subjects the API limits, exercised together.
func TestAPISubjectsAreLimitedIndependently(t *testing.T) {
	l, rdb := integrationLimiter(t, nil)
	flush(t, rdb)

	// Exhaust the per-client budget.
	for range 61 {
		_, _ = l.Allow(t.Context(), "client", "10.0.0.1", 60, time.Minute)
	}
	d, err := l.Allow(t.Context(), "client", "10.0.0.1", 60, time.Minute)
	if err != nil {
		t.Fatalf("Allow: %v", err)
	}
	if d.Allowed {
		t.Error("the per-client budget was not enforced at 60/min")
	}
	if d.Limit != 60 {
		t.Errorf("limit echoed as %d, want 60", d.Limit)
	}

	// The per-fingerprint budget is untouched by that.
	for i := range 10 {
		fd, err := l.Allow(t.Context(), "fingerprint", fmt.Sprintf("fp-%d", i), 10, time.Hour)
		if err != nil {
			t.Fatalf("Allow: %v", err)
		}
		if !fd.Allowed {
			t.Errorf("fingerprint %d was refused below its limit", i)
		}
	}
}

// Redis logical database for the rate-limit tests
//
// The application uses DB 0. Integration tests must not share a Redis database
// with each other either: every test here flushes its database, and `go test
// ./...` runs different packages concurrently. Two packages sharing a database
// would delete each other's keys mid-run, producing failures that look like
// product bugs and are not.
func testRedisDB_LIMIT() int {
	raw := strings.TrimSpace(os.Getenv("REDIS_TEST_DB_LIMIT"))
	if raw == "" {
		return 2
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 2
	}
	return n
}
