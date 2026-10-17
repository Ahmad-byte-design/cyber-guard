package redisqueue

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// Unit tests for the queue operations that need no Redis server.
//
// The behavioural tests against a live Redis live in queue_integration_test.go.

func TestEnqueueRejectsAnEmptyScanID(t *testing.T) {
	t.Parallel()

	c := &Client{}
	if err := c.Enqueue(t.Context(), "   "); err == nil {
		t.Error("Enqueue accepted an empty scan id")
	}
}

func TestEnqueueRejectsAnOverlongScanID(t *testing.T) {
	t.Parallel()

	c := &Client{}
	// The HTTP layer caps scan ids at 64 characters, so anything longer is
	// corrupt and must not reach the queue.
	long := strings.Repeat("a", maxScanIDLen+1)
	if err := c.Enqueue(t.Context(), long); err == nil {
		t.Error("Enqueue accepted an overlong scan id")
	}
}

func TestEnqueueRetryRejectsBadInput(t *testing.T) {
	t.Parallel()

	c := &Client{}
	if err := c.EnqueueRetry(t.Context(), "", time.Second); err == nil {
		t.Error("EnqueueRetry accepted an empty scan id")
	}
	if err := c.EnqueueRetry(t.Context(), strings.Repeat("a", maxScanIDLen+1), time.Second); err == nil {
		t.Error("EnqueueRetry accepted an overlong scan id")
	}
}

// Every operation must be safe on a closed client, because both shutdown paths
// close the datastores while work may still be draining.
func TestQueueOperationsAreSafeOnAClosedClient(t *testing.T) {
	t.Parallel()

	c, err := Connect(t.Context(), Options{Addr: "127.0.0.1:1", PingTimeout: 100 * time.Millisecond})
	if err == nil {
		t.Fatal("Connect to an unreachable server succeeded")
	}

	if err := c.Enqueue(t.Context(), "scan_1"); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("Enqueue = %v, want redis.ErrClosed", err)
	}
	if _, err := c.Claim(t.Context(), time.Millisecond); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("Claim = %v, want redis.ErrClosed", err)
	}
	if _, err := c.PromoteDue(t.Context(), 10); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("PromoteDue = %v, want redis.ErrClosed", err)
	}
	if _, err := c.Depth(t.Context()); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("Depth = %v, want redis.ErrClosed", err)
	}
	if _, err := c.ScheduledDepth(t.Context()); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("ScheduledDepth = %v, want redis.ErrClosed", err)
	}
}

// A nil client must not panic: both binaries can reach a queue path after a
// failed start.
func TestQueueOperationsAreSafeOnANilClient(t *testing.T) {
	t.Parallel()

	var c *Client
	if err := c.Enqueue(t.Context(), "scan_1"); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("Enqueue on nil = %v, want redis.ErrClosed", err)
	}
	if _, err := c.Claim(t.Context(), time.Millisecond); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("Claim on nil = %v, want redis.ErrClosed", err)
	}
	if _, err := c.PromoteDue(t.Context(), 10); !errors.Is(err, redis.ErrClosed) {
		t.Errorf("PromoteDue on nil = %v, want redis.ErrClosed", err)
	}
}

// Validate scans the identifiers the API generates: they are 37 characters and
// fit inside the cap the queue enforces.
func TestGeneratedScanIDsFitTheQueueLimit(t *testing.T) {
	t.Parallel()

	id := "scan_" + strings.Repeat("0", 32)
	if len(id) > maxScanIDLen {
		t.Fatalf("a generated scan id is %d characters, over the %d limit", len(id), maxScanIDLen)
	}
	if err := (&Client{}).Enqueue(t.Context(), id); err == nil {
		t.Error("expected a connection error from the closed client, not success")
	}
}
