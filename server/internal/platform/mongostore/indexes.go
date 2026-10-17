package mongostore

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

// Collection names.
const (
	CollectionScans         = "scans"
	CollectionAssessments   = "assessments"
	CollectionTransientURLs = "transient_urls"
)

// Index names, so EnsureIndexes is idempotent and a mismatch is identifiable.
const (
	idxScansUniqueActive    = "uniq_active_scan"
	idxScansFingerprintNew  = "by_fingerprint_recent"
	idxScansStatusUpdated   = "by_status_updated"
	idxScansProviderScanID  = "by_provider_scan_id"
	idxScansClaimable       = "by_claimable"
	idxAssessmentsExpiresAt = "ttl_expires_at"
	idxAssessmentsHostname  = "by_hostname"
	idxAssessmentsDomain    = "by_domain"
	idxAssessmentsScanID    = "by_scan_id"
	idxTransientExpiresAt   = "ttl_expires_at"
)

// EnsureIndexes creates every index the repository relies on.
//
// It is idempotent: running it against an already-indexed database is a no-op.
// It is a separate step from application startup by design — a process that
// cannot create indexes should still be able to serve reads against a database
// an operator has prepared.
//
// A raw URL and a provider API key are never indexed. The only URL-derived
// value persisted is the HMAC fingerprint, which is already a fixed-size hash
// and therefore bounded in index size.
func (s *Store) EnsureIndexes(ctx context.Context) error {
	if s == nil || s.db == nil {
		return ErrClosed
	}

	// scans
	//
	// The partial unique index is the correctness guarantee behind "at most one
	// active scan per URL". It lets N concurrent requests for the same URL
	// produce exactly one provider submission, without a lock, because the
	// database rejects the second insert.
	//
	// It is partial so that completed and failed scans for the same fingerprint
	// accumulate freely: history must not be constrained by a uniqueness rule
	// that only makes sense while a scan is in flight.
	_, err := s.db.Collection(CollectionScans).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "url_fingerprint", Value: 1}},
			Options: options.Index().
				SetName(idxScansUniqueActive).
				SetUnique(true).
				SetPartialFilterExpression(bson.D{
					{Key: "status", Value: bson.D{{Key: "$in", Value: []ScanStatus{ScanQueued, ScanRunning}}}},
				}),
		},
		{
			// Backs `POST /api/v1/get-url`, which resolves a URL to its most
			// recent scan. The partial index above cannot serve it: that one
			// only contains active scans, and this query asks for the newest of
			// any status. Without this index the lookup degrades to a collection
			// scan, which is O(history) for a URL scanned many times.
			Keys:    bson.D{{Key: "url_fingerprint", Value: 1}, {Key: "created_at", Value: -1}},
			Options: options.Index().SetName(idxScansFingerprintNew),
		},
		{
			// Job recovery and operational queries: "what is stuck, and since
			// when". Ordered by updated_at so the stalest surfaces first.
			Keys:    bson.D{{Key: "status", Value: 1}, {Key: "updated_at", Value: 1}},
			Options: options.Index().SetName(idxScansStatusUpdated),
		},
		{
			// The work-claiming query. Claimable means: an active status, due
			// (available_at), and either unclaimed or holding a lapsed lease.
			//
			// This is the only index whose miss would hurt correctness rather
			// than merely latency — without it every consumer poll is a
			// collection scan over all history, and claims get slower forever.
			Keys: bson.D{
				{Key: "status", Value: 1},
				{Key: "available_at", Value: 1},
				{Key: "lease_expires_at", Value: 1},
			},
			Options: options.Index().SetName(idxScansClaimable),
		},
		{
			// Lets a restarted worker find an in-flight submission by the
			// provider job ID and resume polling rather than re-submitting.
			// Partial: most scans have no provider ID yet.
			Keys: bson.D{{Key: "provider_scan_id", Value: 1}},
			Options: options.Index().
				SetName(idxScansProviderScanID).
				SetPartialFilterExpression(bson.D{
					{Key: "provider_scan_id", Value: bson.D{{Key: "$exists", Value: true}}},
				}),
		},
	})
	if err != nil {
		return fmt.Errorf("mongostore: scans indexes: %w", err)
	}

	// assessments
	//
	// _id is the URL fingerprint, so the unique constraint and the hot lookup
	// are the same operation and no separate index is needed.
	//
	// This is the one collection whose retention policy explicitly permits
	// automatic deletion: a verdict is worthless once stale, and docs/data-model.md
	// §2 commits to deleting at expiry.
	_, err = s.db.Collection(CollectionAssessments).Indexes().CreateMany(ctx, []mongo.IndexModel{
		{
			Keys: bson.D{{Key: "expires_at", Value: 1}},
			Options: options.Index().
				SetName(idxAssessmentsExpiresAt).
				SetExpireAfterSeconds(0),
		},
		{
			Keys:    bson.D{{Key: "hostname", Value: 1}},
			Options: options.Index().SetName(idxAssessmentsHostname),
		},
		{
			Keys:    bson.D{{Key: "registrable_domain", Value: 1}},
			Options: options.Index().SetName(idxAssessmentsDomain),
		},
		{
			Keys:    bson.D{{Key: "scan_id", Value: 1}},
			Options: options.Index().SetName(idxAssessmentsScanID),
		},
	})
	if err != nil {
		return fmt.Errorf("mongostore: assessments indexes: %w", err)
	}

	// transient_urls
	//
	// TTL is a safety net, not the deletion mechanism. ADR 0013 requires an
	// explicit Delete the moment a submission completes; this index only exists
	// to clean up after a worker crash between storing and deleting.
	_, err = s.db.Collection(CollectionTransientURLs).Indexes().CreateOne(ctx, mongo.IndexModel{
		Keys: bson.D{{Key: "expires_at", Value: 1}},
		Options: options.Index().
			SetName(idxTransientExpiresAt).
			SetExpireAfterSeconds(0),
	})
	if err != nil {
		return fmt.Errorf("mongostore: transient_urls index: %w", err)
	}

	return nil
}

// ListIndexes returns the index definitions for a collection, for diagnostics
// and for the integration test that asserts the expected shape.
func (s *Store) ListIndexes(ctx context.Context, collection string) ([]bson.M, error) {
	if s == nil || s.db == nil {
		return nil, ErrClosed
	}
	cursor, err := s.db.Collection(collection).Indexes().List(ctx)
	if err != nil {
		return nil, fmt.Errorf("mongostore: list %s indexes: %w", collection, err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var out []bson.M
	if err := cursor.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("mongostore: decode %s indexes: %w", collection, err)
	}
	return out, nil
}
