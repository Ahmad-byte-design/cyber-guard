package ratelimit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Unit tests for the limiter that need no Redis server.
//
// Behaviour against a live Redis lives in ratelimit_integration_test.go.

func TestAllowWithoutARedisClientFailsClosed(t *testing.T) {
	t.Parallel()

	var l *Limiter
	if _, err := l.Allow(t.Context(), "client", "1.2.3.4", 10, time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Allow on a nil limiter = %v, want ErrUnavailable", err)
	}

	// A limiter with no client must also fail closed. Silently allowing here
	// would turn a Redis outage into unbounded provider spend.
	empty := &Limiter{}
	if _, err := empty.Allow(t.Context(), "client", "1.2.3.4", 10, time.Minute); !errors.Is(err, ErrUnavailable) {
		t.Errorf("Allow without a client = %v, want ErrUnavailable", err)
	}
}

// A limit of zero means "not configured", not "reject everything". Rejecting
// every request would be a far more damaging reading of an unset value.
func TestZeroLimitMeansUnlimited(t *testing.T) {
	t.Parallel()

	// Point at a closed client: if the limiter tried to reach Redis it would
	// fail, so a clean result proves the limit check short-circuits.
	l := &Limiter{}
	decision, err := l.Allow(t.Context(), "client", "1.2.3.4", 0, time.Minute)
	if err != nil {
		t.Fatalf("Allow with limit 0 = %v, want no error", err)
	}
	if !decision.Allowed {
		t.Error("a zero limit rejected the request; it should mean unlimited")
	}
}

// Counter keys must not contain the subject: a client address is personal data
// that should not sit in a key listing readable with redis-cli.
func TestCounterKeysAreHashed(t *testing.T) {
	t.Parallel()

	key := keyFor("client", "203.0.113.7")
	for _, leak := range []string{"203.0.113.7", "client_ip"} {
		if strings.Contains(key, leak) {
			t.Errorf("counter key %q contains %q", key, leak)
		}
	}
	if !strings.HasPrefix(key, keyPrefix+"client:") {
		t.Errorf("counter key %q is not namespaced and scoped", key)
	}
}

func TestCounterKeysAreBounded(t *testing.T) {
	t.Parallel()

	// A long subject must not produce a long key: Redis keys are bounded in
	// practice by memory, and an unbounded key is a way to consume it.
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

// An unreachable Redis must be reported, never treated as permission.
func TestUnreachableRedisFailsClosed(t *testing.T) {
	t.Parallel()

	// Port 1 on loopback refuses immediately. The driver logger is silenced so
	// the expected connection failures do not fill the test output.
	redis.SetLogger(quietLogger{})
	t.Cleanup(func() { redis.SetLogger(defaultLogger{}) })

	rdb := redis.NewClient(&redis.Options{Addr: "127.0.0.1:1", DialTimeout: 100 * time.Millisecond})
	t.Cleanup(func() { _ = rdb.Close() })

	l := New(rdb, time.Now)
	_, err := l.Allow(t.Context(), "client", "1.2.3.4", 10, time.Minute)
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("Allow with Redis down = %v, want ErrUnavailable", err)
	}
}

// quietLogger discards the driver's internal retry chatter. A test that expects
// a connection failure should not print five dial errors while doing it.
type quietLogger struct{}

func (quietLogger) Printf(_ context.Context, _ string, _ ...any) {}

// defaultLogger satisfies the driver after the test, so a later test in the
// same binary is not silenced.
type defaultLogger struct{}

func (defaultLogger) Printf(_ context.Context, _ string, _ ...any) {}
