//go:build integration

package redisqueue

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// Queue behaviour against a live Redis:
//
//	docker compose up -d redis
//	docker compose run --rm go go test -tags integration ./internal/platform/redisqueue/...

// integrationClient connects to the Compose Redis service.
//
// The tests use a separate logical database from the running application, and
// that separation is load-bearing: these tests flush and drain, so sharing a
// database with a live worker would mean they fought it for every job and
// failed for reasons that had nothing to do with the code. Override with
// REDIS_TEST_DB if your deployment puts the tests elsewhere.
func integrationClient(t *testing.T) (*Client, context.Context) {
	t.Helper()

	addr := os.Getenv("REDIS_ADDR")
	if addr == "" {
		addr = "redis:6379"
	}

	db := testRedisDB_QUEUE()

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	c, err := Connect(ctx, Options{Addr: addr, DB: db, PingTimeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Connect(%s): %v", addr, err)
	}
	t.Cleanup(func() { _ = c.Close() })

	// Every test starts from an empty queue. Leaking state between tests turns
	// a real ordering bug into a mystery, and the suite shares one Redis
	// database.
	flush(t, c)

	// The cleanup runs after the test body, at which point t.Context() is
	// already cancelled — so it must use its own context. It also must not
	// fail the test: a cleanup that calls t.Fatalf after the body has
	// finished leaves the next test reading leaked state.
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := c.rdb.FlushDB(ctx).Err(); err != nil {
			t.Logf("cleanup flush failed: %v", err)
		}
	})

	return c, t.Context()
}

func flush(t *testing.T, c *Client) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := c.rdb.FlushDB(ctx).Err(); err != nil {
		t.Fatalf("flush: %v", err)
	}
}

// A job enqueued is the job claimed, and nothing else.
func TestEnqueueThenClaim(t *testing.T) {
	c, ctx := integrationClient(t)

	if err := c.Enqueue(ctx, "scan_aaa"); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	job, err := c.Claim(ctx, time.Second)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if job.ScanID != "scan_aaa" {
		t.Errorf("claimed %q, want scan_aaa", job.ScanID)
	}
	if !job.Valid() {
		t.Error("claimed job reports itself invalid")
	}
}

// Jobs come back in the order they were added, so two URLs submitted in order
// are analysed in order.
func TestClaimIsFIFO(t *testing.T) {
	c, ctx := integrationClient(t)

	want := []string{"scan_1", "scan_2", "scan_3"}
	for _, id := range want {
		if err := c.Enqueue(ctx, id); err != nil {
			t.Fatalf("Enqueue(%s): %v", id, err)
		}
	}

	for i, expected := range want {
		job, err := c.Claim(ctx, time.Second)
		if err != nil {
			t.Fatalf("Claim %d: %v", i, err)
		}
		if job.ScanID != expected {
			t.Errorf("claim %d = %q, want %q", i, job.ScanID, expected)
		}
	}
}

// An empty queue reports ErrNoJob rather than blocking forever or returning a
// zero value the caller would process as a real scan.
func TestClaimOnAnEmptyQueueReturnsErrNoJob(t *testing.T) {
	c, ctx := integrationClient(t)

	start := time.Now()
	_, err := c.Claim(ctx, 200*time.Millisecond)
	if !errors.Is(err, ErrNoJob) {
		t.Fatalf("Claim = %v, want ErrNoJob", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Errorf("Claim blocked for %s; the block timeout was not honoured", elapsed)
	}
}

// A sub-second block must still wait, not degrade into a busy loop. Redis
// takes whole seconds, so rounding down to zero would spin the consumer.
func TestSubSecondBlockDoesNotBusyLoop(t *testing.T) {
	c, ctx := integrationClient(t)

	done := make(chan error, 1)
	go func() {
		_, err := c.Claim(ctx, 10*time.Millisecond)
		done <- err
	}()

	select {
	case err := <-done:
		if !errors.Is(err, ErrNoJob) {
			t.Fatalf("Claim = %v, want ErrNoJob", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Claim with a 10ms block did not return within 3s; it is spinning")
	}
}

// A scheduled retry becomes visible only after its delay, and only when the
// worker promotes it.
func TestRetryIsPromotedOnlyWhenDue(t *testing.T) {
	c, ctx := integrationClient(t)

	if err := c.EnqueueRetry(ctx, "scan_retry", 10*time.Millisecond); err != nil {
		t.Fatalf("EnqueueRetry: %v", err)
	}

	depth, err := c.ScheduledDepth(ctx)
	if err != nil {
		t.Fatalf("ScheduledDepth: %v", err)
	}
	if depth != 1 {
		t.Fatalf("scheduled depth = %d, want 1", depth)
	}

	// A retry that is not yet due stays invisible.
	if n, err := c.Depth(ctx); err != nil || n != 0 {
		t.Fatalf("pending depth = %d (err %v), want 0: a retry must not jump the queue", n, err)
	}

	time.Sleep(30 * time.Millisecond)
	promoted, err := c.PromoteDue(ctx, 100)
	if err != nil {
		t.Fatalf("PromoteDue: %v", err)
	}
	if promoted != 1 {
		t.Fatalf("promoted %d, want 1", promoted)
	}

	// It leaves the scheduled set, so a second tick does not duplicate it.
	if depth, _ := c.ScheduledDepth(ctx); depth != 0 {
		t.Errorf("scheduled depth = %d after promotion, want 0", depth)
	}
	job, err := c.Claim(ctx, time.Second)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if job.ScanID != "scan_retry" {
		t.Errorf("claimed %q, want scan_retry", job.ScanID)
	}
}

// Promotion must be atomic: a crash between removing a member and pushing it
// would leave it scheduled forever and invisible to every future tick.
func TestPromoteDueIsIdempotentAcrossTicks(t *testing.T) {
	c, ctx := integrationClient(t)

	for i := range 5 {
		if err := c.EnqueueRetry(ctx, fmt.Sprintf("scan_%d", i), 5*time.Millisecond); err != nil {
			t.Fatalf("EnqueueRetry: %v", err)
		}
	}
	time.Sleep(20 * time.Millisecond)

	first, err := c.PromoteDue(ctx, 100)
	if err != nil {
		t.Fatalf("PromoteDue: %v", err)
	}
	second, err := c.PromoteDue(ctx, 100)
	if err != nil {
		t.Fatalf("PromoteDue: %v", err)
	}

	if first != 5 {
		t.Errorf("first tick promoted %d, want 5", first)
	}
	if second != 0 {
		t.Errorf("second tick promoted %d, want 0: a retry was duplicated", second)
	}
	if n, _ := c.Depth(ctx); n != 5 {
		t.Errorf("pending depth = %d, want 5", n)
	}
}

// A retry past its due time is honoured within the promote limit; the rest wait
// for the next tick rather than being dropped.
func TestPromoteDueRespectsItsLimit(t *testing.T) {
	c, ctx := integrationClient(t)

	for i := range 10 {
		if err := c.EnqueueRetry(ctx, fmt.Sprintf("scan_%d", i), time.Millisecond); err != nil {
			t.Fatalf("EnqueueRetry: %v", err)
		}
	}
	time.Sleep(20 * time.Millisecond)

	promoted, err := c.PromoteDue(ctx, 4)
	if err != nil {
		t.Fatalf("PromoteDue: %v", err)
	}
	if promoted != 4 {
		t.Errorf("promoted %d, want the limit of 4", promoted)
	}
	remaining, err := c.ScheduledDepth(ctx)
	if err != nil {
		t.Fatalf("ScheduledDepth: %v", err)
	}
	if remaining != 6 {
		t.Errorf("scheduled depth = %d, want 6: promotion dropped work", remaining)
	}
}

// A corrupt message is rejected rather than forwarded to the database, which
// would otherwise fail with a confusing "no scan record" for every delivery.
func TestClaimRejectsAMalformedMessage(t *testing.T) {
	c, ctx := integrationClient(t)

	if err := c.rdb.RPush(ctx, keyQueue, "   ").Err(); err != nil {
		t.Fatalf("RPush: %v", err)
	}

	if _, err := c.Claim(ctx, time.Second); !errors.Is(err, ErrJobInvalid) {
		t.Errorf("Claim = %v, want ErrJobInvalid", err)
	}
}

// The payload is a bare scan identifier: nothing a client would recognise as a
// URL ever enters the queue.
func TestQueuePayloadIsAnOpaqueIdentifier(t *testing.T) {
	c, ctx := integrationClient(t)

	const scanID = "scan_0123456789abcdef0123456789abcdef"
	if err := c.Enqueue(ctx, scanID); err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	values, err := c.rdb.LRange(ctx, keyQueue, 0, -1).Result()
	if err != nil {
		t.Fatalf("LRange: %v", err)
	}
	if len(values) != 1 || values[0] != scanID {
		t.Fatalf("queue holds %v, want exactly [%s]", values, scanID)
	}
	for _, v := range values {
		if len(v) != len(scanID) {
			t.Errorf("payload %q is %d bytes; a scan id must be the whole message", v, len(v))
		}
	}
}

// Concurrent producers and consumers must not lose or duplicate a job.
func TestConcurrentEnqueueAndClaimLosesNothing(t *testing.T) {
	c, ctx := integrationClient(t)

	const producers = 8
	const perProducer = 25

	errCh := make(chan error, producers)
	for p := range producers {
		go func() {
			for i := range perProducer {
				if err := c.Enqueue(ctx, fmt.Sprintf("scan_%d_%d", p, i)); err != nil {
					errCh <- err
					return
				}
			}
			errCh <- nil
		}()
	}
	for range producers {
		if err := <-errCh; err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
	}

	depth, err := c.Depth(ctx)
	if err != nil {
		t.Fatalf("Depth: %v", err)
	}
	if depth != producers*perProducer {
		t.Fatalf("depth = %d, want %d", depth, producers*perProducer)
	}

	seen := make(map[string]bool, depth)
	for range depth {
		job, err := c.Claim(ctx, 2*time.Second)
		if err != nil {
			t.Fatalf("Claim: %v", err)
		}
		if seen[job.ScanID] {
			t.Errorf("job %s was delivered twice", job.ScanID)
		}
		seen[job.ScanID] = true
	}
	if len(seen) != int(depth) {
		t.Errorf("claimed %d distinct jobs, want %d", len(seen), depth)
	}
}

// A blocking pop must be interruptible, or a worker would ignore shutdown for
// as long as its block lasts.
//
// This was verified against the driver rather than assumed: go-redis applies a
// context *deadline* to a socket read but does not act on plain cancellation
// while a read is in flight. Claim therefore derives a deadline from its own
// block, which is what makes the two cases below behave.
func TestBlockingPopIsInterruptible(t *testing.T) {
	t.Run("caller deadline", func(t *testing.T) {
		c, _ := integrationClient(t)

		ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
		defer cancel()

		start := time.Now()
		if _, err := c.Claim(ctx, 30*time.Second); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("Claim = %v, want context.DeadlineExceeded", err)
		}
		if elapsed := time.Since(start); elapsed > 3*time.Second {
			t.Errorf("Claim took %s; the caller's deadline was not honoured", elapsed)
		}
	})

	t.Run("derived deadline from the block", func(t *testing.T) {
		c, _ := integrationClient(t)

		// No caller deadline: Claim derives one, so this must return on its
		// own rather than hanging for the full block.
		start := time.Now()
		_, err := c.Claim(t.Context(), 300*time.Millisecond)
		if !errors.Is(err, ErrNoJob) {
			t.Fatalf("Claim = %v, want ErrNoJob", err)
		}
		elapsed := time.Since(start)
		if elapsed > 3*time.Second {
			t.Errorf("Claim took %s; the derived deadline did not bound it", elapsed)
		}
		if elapsed < 300*time.Millisecond {
			t.Errorf("Claim returned after %s, before the 300ms block elapsed", elapsed)
		}
	})
}

// Enqueue must respect context cancellation too: an API request whose client
// disconnected must not block holding the scan open.
func TestEnqueueRespectsContextCancellation(t *testing.T) {
	c, _ := integrationClient(t)

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	if err := c.Enqueue(ctx, "scan_x"); err == nil {
		t.Error("Enqueue succeeded with a cancelled context")
	}
}

// The queue operations must tolerate concurrent use, because every worker
// goroutine and the reconciler share one client.
func TestConcurrentUseOfOneClient(t *testing.T) {
	c, ctx := integrationClient(t)

	done := make(chan struct{})
	for range 8 {
		go func() {
			defer func() { done <- struct{}{} }()
			for i := range 50 {
				_ = c.Enqueue(ctx, fmt.Sprintf("scan_%d", i))
				_, _ = c.Depth(ctx)
				_, _ = c.PromoteDue(ctx, 10)
				_ = c.EnqueueRetry(ctx, fmt.Sprintf("scan_r_%d", i), time.Millisecond)
			}
		}()
	}
	for range 8 {
		<-done
	}
}

// Redis logical database for the queue tests
//
// The application uses DB 0. Integration tests must not share a Redis database
// with each other either: every test here flushes its database, and `go test
// ./...` runs different packages concurrently. Two packages sharing a database
// would delete each other's keys mid-run, producing failures that look like
// product bugs and are not.
func testRedisDB_QUEUE() int {
	raw := strings.TrimSpace(os.Getenv("REDIS_TEST_DB_QUEUE"))
	if raw == "" {
		return 1
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n < 0 {
		return 1
	}
	return n
}
