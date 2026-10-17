package mongoqueue

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"cyberguard/server/internal/platform/mongostore"
)

// fakeStore is an in-memory stand-in for the scans collection that reproduces
// lease semantics rather than enqueue/pop semantics.
//
// That distinction matters: the whole point of the queue is that a claim is a
// time-bounded lease, so a double that modelled a pop would make every test
// below pass for the wrong reason.
//
// Model: every scan has an optional available_at (absent means "due now") and
// an optional lease. Claimable means due and unleased-or-lease-lapsed, exactly
// as the MongoDB query tests it.
type fakeStore struct {
	mu sync.Mutex

	availableAt map[string]time.Time
	leasedUntil map[string]time.Time

	claimErr error
	claims   int
	released []string
}

func newFakeStore(ids ...string) *fakeStore {
	f := &fakeStore{
		availableAt: make(map[string]time.Time),
		leasedUntil: make(map[string]time.Time),
	}
	for _, id := range ids {
		f.availableAt[id] = time.Time{}
	}
	return f
}

func (f *fakeStore) ClaimNextScan(_ context.Context, now time.Time, lease time.Duration, _ string) (mongostore.Scan, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.claimErr != nil {
		return mongostore.Scan{}, f.claimErr
	}

	// Deterministic order, so a claim is reproducible across runs.
	ids := make([]string, 0, len(f.availableAt))
	for id := range f.availableAt {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		if due, ok := f.availableAt[id]; ok && now.Before(due) {
			continue // deferred into the future
		}
		if until, held := f.leasedUntil[id]; held && now.Before(until) {
			continue // lease still live
		}
		f.leasedUntil[id] = now.Add(lease)
		f.claims++
		return mongostore.Scan{ScanID: id}, nil
	}
	return mongostore.Scan{}, mongostore.ErrNoClaimableScan
}

func (f *fakeStore) ReleaseScanLease(_ context.Context, scanID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.released = append(f.released, scanID)
	// Returning the work to the pool immediately is the property under test, so
	// no clock is needed: a zero available_at means "due now".
	delete(f.leasedUntil, scanID)
	f.availableAt[scanID] = time.Time{}
	return nil
}

func (f *fakeStore) ScheduleScanRetry(_ context.Context, scanID string, at time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.leasedUntil, scanID)
	f.availableAt[scanID] = at
	return nil
}

func newQueue(t *testing.T, store Store, now func() time.Time) *Queue {
	t.Helper()
	q, err := New(Options{
		Store:         store,
		Owner:         "test-host/1",
		LeaseDuration: time.Minute,
		PollGap:       time.Millisecond,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return q
}

func TestNewRejectsAnUnusableConfiguration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts Options
	}{
		{"no store", Options{Owner: "o", LeaseDuration: time.Minute}},
		{"no owner", Options{Store: newFakeStore("a"), LeaseDuration: time.Minute}},
		{"zero lease", Options{Store: newFakeStore("a"), Owner: "o"}},
		{"negative lease", Options{Store: newFakeStore("a"), Owner: "o", LeaseDuration: -time.Second}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.opts); err == nil {
				t.Error("New accepted a configuration it should reject")
			}
		})
	}
}

func TestClaimReturnsTheScanAndLeasesIt(t *testing.T) {
	t.Parallel()

	store := newFakeStore("scan-1")
	q := newQueue(t, store, time.Now)

	job, err := q.Claim(t.Context(), 50*time.Millisecond)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if job.ScanID != "scan-1" {
		t.Errorf("ScanID = %q, want scan-1", job.ScanID)
	}

	// The lease is now held, so a second claim finds nothing and reports idle.
	if _, err := q.Claim(t.Context(), 10*time.Millisecond); !errors.Is(err, ErrNoJob) {
		t.Errorf("second Claim = %v, want ErrNoJob while the lease is held", err)
	}
}

func TestClaimReportsIdleRatherThanFailing(t *testing.T) {
	t.Parallel()

	q := newQueue(t, newFakeStore(), time.Now)

	start := time.Now()
	_, err := q.Claim(t.Context(), 30*time.Millisecond)
	if !errors.Is(err, ErrNoJob) {
		t.Fatalf("Claim on an empty queue = %v, want ErrNoJob", err)
	}
	// The block must actually have been honoured, not returned immediately.
	if elapsed := time.Since(start); elapsed < 25*time.Millisecond {
		t.Errorf("Claim returned after %s, want it to honour the ~30ms block", elapsed)
	}
}

func TestClaimPropagatesAStoreFailure(t *testing.T) {
	t.Parallel()

	store := newFakeStore("scan-1")
	store.claimErr = errors.New("mongo exploded")
	q := newQueue(t, store, time.Now)

	_, err := q.Claim(t.Context(), 50*time.Millisecond)
	if err == nil {
		t.Fatal("Claim hid a store failure")
	}
	if errors.Is(err, ErrNoJob) {
		t.Error("a store failure was reported as an idle queue")
	}
}

// A lapsed lease must return the work without any sweeper, which is the
// recovery path for a consumer that crashed mid-job.
func TestALapsedLeaseReturnsTheWork(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	store := newFakeStore("scan-1")
	q := newQueue(t, store, func() time.Time { return now })

	if _, err := q.Claim(t.Context(), 20*time.Millisecond); err != nil {
		t.Fatalf("first Claim: %v", err)
	}

	// Inside the lease: nothing available.
	now = now.Add(30 * time.Second)
	if _, err := q.Claim(t.Context(), 5*time.Millisecond); !errors.Is(err, ErrNoJob) {
		t.Errorf("Claim inside the lease = %v, want ErrNoJob", err)
	}

	// Past the lease: claimable again, with no cleanup step in between.
	now = now.Add(31 * time.Second)
	job, err := q.Claim(t.Context(), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("Claim after the lease lapsed: %v", err)
	}
	if job.ScanID != "scan-1" {
		t.Errorf("ScanID = %q, want the lapsed scan reclaimed", job.ScanID)
	}
}

// Releasing a lease must make the work claimable at once. Relying on expiry
// instead would add a whole lease of latency to every retry.
func TestReleaseReturnsWorkImmediately(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	store := newFakeStore("scan-1")
	q := newQueue(t, store, func() time.Time { return now })

	first, err := q.Claim(t.Context(), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := q.Release(t.Context(), first.ScanID); err != nil {
		t.Fatalf("Release: %v", err)
	}

	// A single second later — far inside the one-minute lease.
	now = now.Add(time.Second)
	again, err := q.Claim(t.Context(), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("Claim after Release: %v", err)
	}
	if again.ScanID != "scan-1" {
		t.Errorf("ScanID = %q, want the released scan", again.ScanID)
	}
	if len(store.released) != 1 {
		t.Errorf("released %d times, want 1", len(store.released))
	}
}

// A retry must not become claimable until its delay has elapsed. Getting this
// wrong produces a hot loop that spends provider quota as fast as it can.
func TestEnqueueRetryDefersTheWork(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	store := newFakeStore("scan-1")
	q := newQueue(t, store, func() time.Time { return now })

	if _, err := q.Claim(t.Context(), 20*time.Millisecond); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := q.EnqueueRetry(t.Context(), "scan-1", 30*time.Second); err != nil {
		t.Fatalf("EnqueueRetry: %v", err)
	}

	now = now.Add(20 * time.Second)
	if _, err := q.Claim(t.Context(), 5*time.Millisecond); !errors.Is(err, ErrNoJob) {
		t.Errorf("Claim before the retry was due = %v, want ErrNoJob", err)
	}

	now = now.Add(11 * time.Second)
	job, err := q.Claim(t.Context(), 20*time.Millisecond)
	if err != nil {
		t.Fatalf("Claim after the retry came due: %v", err)
	}
	if job.ScanID != "scan-1" {
		t.Errorf("ScanID = %q, want the deferred scan", job.ScanID)
	}
}

// Two consumers competing for one scan must not both win it. The real guarantee
// comes from an atomic FindOneAndUpdate; this asserts the adapter does not
// serialise work behind anything that would let a double through.
func TestConcurrentConsumersDoNotShareOneScan(t *testing.T) {
	t.Parallel()

	store := newFakeStore("scan-1")
	q := newQueue(t, store, time.Now)

	const consumers = 8
	var wg sync.WaitGroup
	won := make(chan string, consumers)
	for range consumers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if job, err := q.Claim(t.Context(), 20*time.Millisecond); err == nil {
				won <- job.ScanID
			}
		}()
	}
	wg.Wait()
	close(won)

	ids := []string{}
	for id := range won {
		ids = append(ids, id)
	}
	if len(ids) != 1 {
		t.Errorf("%d consumers claimed the single scan %v, want exactly 1", len(ids), ids)
	}
}

// PromoteDue exists to satisfy the delivery interface and must report zero
// without claiming otherwise: there is no set of entries to move.
func TestPromoteDueIsInert(t *testing.T) {
	t.Parallel()

	q := newQueue(t, newFakeStore("scan-1"), time.Now)
	n, err := q.PromoteDue(t.Context(), 100)
	if err != nil {
		t.Fatalf("PromoteDue: %v", err)
	}
	if n != 0 {
		t.Errorf("PromoteDue = %d, want 0", n)
	}
}

// Enqueue is deliberately inert. It must still reject an empty ID so a caller
// bug cannot look like a successful enqueue.
func TestEnqueueAcceptsAScanAndRejectsNothing(t *testing.T) {
	t.Parallel()

	q := newQueue(t, newFakeStore(), time.Now)
	if err := q.Enqueue(t.Context(), "scan-1"); err != nil {
		t.Errorf("Enqueue: %v", err)
	}
	if err := q.Enqueue(t.Context(), ""); err == nil {
		t.Error("Enqueue accepted an empty scan id")
	}
}

// A cancelled context must end a blocked Claim rather than spinning until the
// block expires, so shutdown is prompt.
func TestClaimStopsOnCancellation(t *testing.T) {
	t.Parallel()

	q := newQueue(t, newFakeStore(), time.Now)
	ctx, cancel := context.WithCancel(t.Context())

	done := make(chan error, 1)
	go func() {
		_, err := q.Claim(ctx, 10*time.Second)
		done <- err
	}()

	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("Claim = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Claim ignored cancellation and kept polling")
	}
}
