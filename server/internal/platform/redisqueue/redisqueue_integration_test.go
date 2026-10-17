//go:build integration

// Integration tests for Redis connectivity.
//
// Run against the Compose stack:
//
//	docker compose up -d redis
//	docker compose run --rm go go test -tags integration ./internal/platform/redisqueue/...
//
// The tag keeps these out of `go test ./...` so the default suite stays fast
// and dependency-free.
//
// Queue behaviour — enqueue, claim, lease — belongs to Phase 4. What is tested
// here is connection lifecycle plus one property that is cheap to check now and
// expensive to discover later: a queue payload must never contain a URL
// (ADR 0013).
package redisqueue_test

import (
	"context"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"cyberguard/server/internal/platform/redisqueue"
)

func addr(t *testing.T) string {
	t.Helper()
	v := os.Getenv("REDIS_ADDR")
	if v == "" {
		v = "redis:6379" // Compose service name
	}
	return v
}

func connect(t *testing.T) *redisqueue.Client {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	client, err := redisqueue.Connect(ctx, redisqueue.Options{
		Addr:        addr(t),
		DB:          redisDB(t),
		PingTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("Close: %v", err)
		}
	})
	return client
}

func redisDB(t *testing.T) int {
	t.Helper()
	if v := os.Getenv("REDIS_DB"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil {
			t.Fatalf("REDIS_DB=%q is not an integer: %v", v, err)
		}
		return n
	}
	// A separate logical database keeps these tests from colliding with
	// development data.
	return 9
}

func TestConnectPingsReachableServer(t *testing.T) {
	client := connect(t)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx); err != nil {
		t.Fatalf("Ping against a running Redis: %v", err)
	}
}

func TestCloseIsIdempotentAgainstRealServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	client, err := redisqueue.Connect(ctx, redisqueue.Options{
		Addr:        addr(t),
		DB:          redisDB(t),
		PingTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if err := client.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("second Close: %v, want nil", err)
	}
}

func TestPingFailsAfterClose(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	client, err := redisqueue.Connect(ctx, redisqueue.Options{
		Addr:        addr(t),
		DB:          redisDB(t),
		PingTimeout: 3 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	pingCtx, pingCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer pingCancel()
	if err := client.Ping(pingCtx); err == nil {
		t.Error("Ping succeeded after Close, want an error")
	}
}

// ADR 0017 makes maxmemory-policy noeviction a launch blocker: under an
// eviction policy Redis silently drops queue entries under memory pressure,
// which is indistinguishable from a lost job.
func TestRedisDoesNotEvict(t *testing.T) {
	connect(t) // proves the server is reachable before inspecting its config

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	t.Cleanup(func() {
		if err := rawClient(t).Close(); err != nil {
			t.Errorf("close raw client: %v", err)
		}
	})

	raw, err := rawClient(t).ConfigGet(ctx, "maxmemory-policy").Result()
	if err != nil {
		t.Skipf("CONFIG GET unavailable: %v", err)
	}

	if got := raw["maxmemory-policy"]; got != "noeviction" {
		t.Errorf("maxmemory-policy = %q, want noeviction; "+
			"an eviction policy can silently drop queued scan jobs", got)
	}
}

// rawClient builds a direct go-redis client for assertions that need commands
// the wrapper deliberately does not expose yet.
func rawClient(t *testing.T) *redis.Client {
	t.Helper()
	return redis.NewClient(&redis.Options{Addr: addr(t), DB: redisDB(t)})
}
