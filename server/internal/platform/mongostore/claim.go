package mongostore

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Work claiming, expressed as leases on scan documents.
//
// # Why the scans collection is the queue
//
// This replaces a Redis list plus a Redis sorted set of deferred retries. Two
// properties made the broker worth removing:
//
//   - The scans collection was already the durable ledger. A scan was written
//     there before it was enqueued, so every job in Redis had a document behind
//     it and every document had a recovery path that re-enqueued it. The queue
//     was a second source of truth about work the first one already knew about,
//     and keeping the two in step was the reconciler's whole job.
//
//   - Delivery was never the hard part. Processing a scan twice is already a
//     no-op: Process() returns immediately for a finished scan, and a scan that
//     already carries a provider scan ID polls instead of submitting. So the
//     strongest thing a broker could guarantee — at-most-once — was never
//     actually load-bearing. What is load-bearing is that work is not lost.
//
// Losing nothing is exactly what a lease on the ledger gives, and it gives it
// with one fewer process and one fewer failure mode to reason about.
//
// # The lease, and why it expires
//
// Claiming is a single atomic FindOneAndUpdate that matches a claimable document
// and stamps a lease on it in the same operation. Two consumers therefore cannot
// claim the same scan: the second find matches nothing, because the first
// update already moved the document out of the claimable set.
//
// A lease is time-bounded rather than permanent. A consumer that crashes — or is
// SIGKILLed mid-poll — releases nothing, and a permanent claim would strand the
// scan forever with no process left to notice. The expiry is the recovery
// mechanism: no sweeper, no reaper, no cleanup step. The clock does it.
//
// The lease must therefore be longer than the longest plausible unit of work,
// which for this system is a provider poll bounded by PollDeadline. A lease
// shorter than that would let a second consumer start on a scan whose analysis
// is still running. That constraint is enforced where the two are configured
// together; see the worker wiring.

// ClaimNextScan atomically leases the oldest claimable scan.
//
// It returns ErrNoClaimableScan when nothing is due, which is an ordinary idle
// condition and not an error the caller should surface.
//
// owner identifies the consumer in the lease record. It is diagnostic only — the
// lease is released by expiry or by releaseScanLease, never by matching owner —
// so a consumer that dies under a new name cannot strand its work.
func (s *Store) ClaimNextScan(ctx context.Context, now time.Time, leaseDuration time.Duration, owner string) (Scan, error) {
	if s == nil || s.db == nil {
		return Scan{}, ErrClosed
	}
	if leaseDuration <= 0 {
		return Scan{}, fmt.Errorf("mongostore: claim lease must be positive, got %s", leaseDuration)
	}

	now = now.UTC()
	leaseUntil := now.Add(leaseDuration)

	filter := bson.M{
		"status": bson.M{"$in": activeStatuses},
		"$and": []bson.M{
			// Due: either explicitly at or before now, or absent entirely.
			//
			// The absent case is not a nicety. `{"available_at": {"$lte": now}}`
			// does NOT match a document where the field is missing — MongoDB does
			// not compare a missing field against a date in the query language —
			// so without this branch every scan written before the lease fields
			// existed would be stranded permanently and never picked up again.
			{"$or": []bson.M{
				{"available_at": bson.M{"$exists": false}},
				{"available_at": bson.M{"$lte": now}},
			}},
			// Unleased, or holding a lease that has lapsed.
			{"$or": []bson.M{
				{"lease_expires_at": bson.M{"$exists": false}},
				{"lease_expires_at": nil},
				{"lease_expires_at": bson.M{"$lte": now}},
			}},
		},
	}

	set := bson.M{
		"lease_owner":      owner,
		"lease_expires_at": leaseUntil,
		"available_at":     now,
		"updated_at":       now,
	}

	var scan Scan
	err := s.db.Collection(CollectionScans).
		FindOneAndUpdate(ctx, filter,
			bson.M{"$set": set},
			options.FindOneAndUpdate().
				SetSort(bson.D{{Key: "available_at", Value: 1}, {Key: "created_at", Value: 1}}).
				SetReturnDocument(options.After)).
		Decode(&scan)

	switch {
	case err == nil:
		return scan, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Scan{}, ErrNoClaimableScan
	default:
		return Scan{}, fmt.Errorf("mongostore: claim scan: %w", err)
	}
}

// ReleaseScanLease returns a leased scan to the claimable pool immediately.
//
// It is called when work ends without the scan reaching a terminal status, so a
// retry does not have to wait out the lease. It is deliberately not
// owner-matched: releasing is only ever a best-effort optimisation, and refusing
// to release a lease held by a previous incarnation of this consumer would leave
// the work waiting for an expiry that recovery already decided was unnecessary.
func (s *Store) ReleaseScanLease(ctx context.Context, scanID string) error {
	if s == nil || s.db == nil {
		return ErrClosed
	}
	if scanID == "" {
		return fmt.Errorf("mongostore: release lease requires a scan id")
	}

	_, err := s.db.Collection(CollectionScans).UpdateOne(ctx,
		bson.M{"_id": scanID},
		bson.M{
			"$unset": bson.M{"lease_owner": "", "lease_expires_at": ""},
			"$set":   bson.M{"available_at": time.Now().UTC()},
		})
	if err != nil {
		return fmt.Errorf("mongostore: release lease: %w", err)
	}
	return nil
}

// ScheduleScanRetry defers a scan until at, releasing any lease it holds.
//
// This is the replacement for the Redis sorted set that used to hold retries
// waiting for a retry-after delay. Storing the due time on the document is what
// lets the claim query filter on time directly instead of requiring a promoter
// to move entries between structures.
func (s *Store) ScheduleScanRetry(ctx context.Context, scanID string, at time.Time) error {
	if s == nil || s.db == nil {
		return ErrClosed
	}
	if scanID == "" {
		return fmt.Errorf("mongostore: schedule retry requires a scan id")
	}

	_, err := s.db.Collection(CollectionScans).UpdateOne(ctx,
		bson.M{"_id": scanID},
		bson.M{
			"$set":   bson.M{"available_at": at.UTC()},
			"$unset": bson.M{"lease_owner": "", "lease_expires_at": ""},
		})
	if err != nil {
		return fmt.Errorf("mongostore: schedule retry: %w", err)
	}
	return nil
}
