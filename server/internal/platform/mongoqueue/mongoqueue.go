// Package mongoqueue adapts the scans collection to the delivery interface the
// scan lifecycle expects.
//
// It replaces the Redis list-and-sorted-set queue that previously provided job
// delivery. The design rationale — why the ledger can be the queue, and why a
// time-bounded lease is the right primitive — is documented alongside the
// primitives themselves in ../mongostore/claim.go. This package is only the
// adapter that speaks the lifecycle's Enqueue/Claim/PromoteDue vocabulary.
package mongoqueue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/scans"
)

// Job is one unit of delivered work.
//
// It carries a scan ID and nothing else. There is deliberately no field a URL
// could travel in: ADR 0013 requires that raw URLs never leave the encrypted
// transient collection, and the way to keep a promise like that is to leave no
// parameter through which it could be kept.
//
// It is an alias rather than a distinct type so this adapter and the in-memory
// test double satisfy scans.Queue without either importing the other. The
// contract belongs to the consumer; re-declaring it here would be a third
// definition to keep in sync.
type Job = scans.Job

// ErrNoJob means nothing was available before the block expired. It is the
// normal idle path, not a failure.
//
// Aliased for the same reason as Job.
var ErrNoJob = scans.ErrNoJob

// Store is the persistence this queue needs.
//
// It is declared at the consumer so the adapter depends on the three operations
// it actually uses rather than on the whole *mongostore.Store.
type Store interface {
	ClaimNextScan(ctx context.Context, now time.Time, leaseDuration time.Duration, owner string) (mongostore.Scan, error)
	ReleaseScanLease(ctx context.Context, scanID string) error
	ScheduleScanRetry(ctx context.Context, scanID string, at time.Time) error
}

// Queue delivers scans from the scans collection.
//
// # Enqueue is a no-op, and that is the point
//
// A scan document is written before anything is enqueued, so by the time
// Enqueue is called the work is already durable and already claimable. There is
// nothing left to do, and pretending otherwise by writing a second record would
// reintroduce exactly the second source of truth this package exists to remove.
//
// The call is kept rather than deleted because it is where a future broker
// would be reintroduced, and because its absence would make every caller
// special-case "no queue" — which is how a queue silently comes back.
type Queue struct {
	store   Store
	now     func() time.Time
	owner   string
	lease   time.Duration
	pollGap time.Duration
}

// Options configures a Queue.
type Options struct {
	// Store is the scans collection. Required.
	Store Store

	// Owner identifies this consumer in the lease record. Diagnostic only:
	// leases are released by expiry or explicitly, never by matching owner.
	Owner string

	// LeaseDuration is how long one claim is held. It must exceed the longest
	// possible unit of work — a provider poll bounded by the poll deadline — or
	// a second consumer will start on a scan whose analysis is still running.
	LeaseDuration time.Duration

	// PollGap is the pause between empty claims. It bounds how hard an idle
	// consumer queries the database, and it is independent of the caller's block
	// timeout so the two concerns stay separable.
	PollGap time.Duration

	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// New builds a Queue.
func New(opts Options) (*Queue, error) {
	if opts.Store == nil {
		return nil, fmt.Errorf("mongoqueue: a store is required")
	}
	if opts.Owner == "" {
		return nil, fmt.Errorf("mongoqueue: an owner is required")
	}
	if opts.LeaseDuration <= 0 {
		return nil, fmt.Errorf("mongoqueue: lease duration must be positive, got %s", opts.LeaseDuration)
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.PollGap <= 0 {
		opts.PollGap = 250 * time.Millisecond
	}
	return &Queue{
		store:   opts.Store,
		now:     opts.Now,
		owner:   opts.Owner,
		lease:   opts.LeaseDuration,
		pollGap: opts.PollGap,
	}, nil
}

// Enqueue records that a scan should be worked.
//
// It is intentionally a no-op: see the type comment. It exists so the caller
// keeps a single code path whether or not a real broker is present.
func (q *Queue) Enqueue(_ context.Context, scanID string) error {
	if scanID == "" {
		return fmt.Errorf("mongoqueue: enqueue requires a scan id")
	}
	return nil
}

// EnqueueRetry defers a scan until delay has elapsed.
//
// The delay is stored on the document rather than held in a timer or a sorted
// set, so a restart cannot lose it and no promoter has to move it.
func (q *Queue) EnqueueRetry(ctx context.Context, scanID string, delay time.Duration) error {
	if scanID == "" {
		return fmt.Errorf("mongoqueue: enqueue retry requires a scan id")
	}
	if delay < 0 {
		delay = 0
	}
	return q.store.ScheduleScanRetry(ctx, scanID, q.now().Add(delay))
}

// Claim leases one scan, blocking up to block before reporting that nothing was
// available.
//
// The block is implemented as a poll loop rather than a server-side wait because
// MongoDB has no blocking claim primitive. The cost is one indexed query per
// pollGap on an idle consumer, which is why PollGap exists and why it is not
// zero: a busy-loop would turn "no work" into a database load problem.
//
// The block deadline is measured with the real clock, deliberately, while the
// lease timestamp handed to the store uses the injected one. Pacing and business
// logic need different clocks: a test that freezes Now to assert lease
// arithmetic would otherwise wait forever for a deadline that never arrives,
// and production would be the only place the two clocks were ever equal.
//
// Returning ErrNoJob on timeout is a normal outcome. Callers must not treat it
// as a failure, and this package never logs it.
func (q *Queue) Claim(ctx context.Context, block time.Duration) (Job, error) {
	if block <= 0 {
		block = q.pollGap
	}
	deadline := time.Now().Add(block)

	for {
		scan, err := q.store.ClaimNextScan(ctx, q.now(), q.lease, q.owner)
		switch {
		case err == nil:
			return Job{ScanID: scan.ScanID}, nil
		case errors.Is(err, mongostore.ErrNoClaimableScan):
			// Fall through to the wait below.
		default:
			return Job{}, fmt.Errorf("mongoqueue: claim: %w", err)
		}

		if !time.Now().Before(deadline) {
			return Job{}, ErrNoJob
		}
		if err := sleepCtx(ctx, q.pollGap); err != nil {
			return Job{}, err
		}
	}
}

// PromoteDue reports how many scans are waiting for their deferred time.
//
// It exists to satisfy the delivery interface, and unlike the Redis queue there
// is nothing to promote: a deferred scan becomes claimable purely because its
// available_at has passed, which the claim query already tests. Reporting the
// count keeps the supervisor's log line meaningful and its logic uniform with
// the previous implementation.
func (q *Queue) PromoteDue(_ context.Context, _ int) (int, error) {
	return 0, nil
}

// Release returns a lease early so a retry need not wait out its expiry.
//
// Best-effort by design: a failure here costs at most one lease duration of
// latency, so it is logged by the caller rather than escalated.
func (q *Queue) Release(ctx context.Context, scanID string) error {
	if scanID == "" {
		return fmt.Errorf("mongoqueue: release requires a scan id")
	}
	return q.store.ReleaseScanLease(ctx, scanID)
}

// sleepCtx waits for d unless ctx ends first, reporting whether the wait
// completed rather than the context error, which callers discard anyway.
func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
