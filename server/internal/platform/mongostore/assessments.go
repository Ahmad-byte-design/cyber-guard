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

// ErrAssessmentNotFound is returned when no assessment matches.
var ErrAssessmentNotFound = errors.New("mongostore: assessment not found")

// PutAssessment stores a normalised verdict for a URL fingerprint.
//
// It upserts on _id, which is the fingerprint. That makes it idempotent: the
// same assessment written twice is one document, so a retried worker cannot
// create a duplicate verdict.
//
// The assessment's _id being the fingerprint is what makes a duplicate verdict
// for one URL unrepresentable — the same guarantee a unique index would give,
// without a second index to keep in sync.
//
// Only a verdict with a defined value may be stored. An empty or invalid
// verdict is rejected here rather than persisted, because an assessment
// document holding an unknown verdict would be served to the extension as if it
// meant something.
func (s *Store) PutAssessment(ctx context.Context, a Assessment) (Assessment, error) {
	if s == nil || s.db == nil {
		return Assessment{}, ErrClosed
	}
	if a.URLFingerprint == "" {
		return Assessment{}, errors.New("mongostore: URLFingerprint is required")
	}
	if a.ScanID == "" {
		return Assessment{}, errors.New("mongostore: ScanID is required")
	}
	if !a.Verdict.Valid() {
		return Assessment{}, fmt.Errorf("mongostore: invalid verdict %q", a.Verdict)
	}
	if a.ExpiresAt.IsZero() {
		return Assessment{}, errors.New("mongostore: ExpiresAt is required")
	}

	now := time.Now().UTC()
	if a.CreatedAt.IsZero() {
		a.CreatedAt = now
	}
	a.UpdatedAt = now

	// Bound every string that reaches the browser extension.
	const maxSummaryLen = 500
	for i := range a.Evidence {
		if len(a.Evidence[i].Summary) > maxSummaryLen {
			a.Evidence[i].Summary = a.Evidence[i].Summary[:maxSummaryLen]
		}
	}

	var stored Assessment
	err := s.db.Collection(CollectionAssessments).
		FindOneAndUpdate(ctx,
			bson.M{"_id": a.URLFingerprint},
			bson.M{"$set": bson.M{
				"scan_id":            a.ScanID,
				"hostname":           a.Hostname,
				"registrable_domain": a.RegistrableDomain,
				// Written for every upsert so that re-running an assessment with
				// a cleared field actually clears it in the document. Omitting
				// them would leave a stale path behind on a verdict that no
				// longer justifies one.
				"scheme":           a.Scheme,
				"path_prefix":      a.PathPrefix,
				"verdict":          a.Verdict,
				"provider":         a.Provider,
				"provider_scan_id": a.ProviderScanID,
				"evidence":         a.Evidence,
				"analyzed_at":      a.AnalyzedAt,
				"expires_at":       a.ExpiresAt,
				"updated_at":       now,
				"created_at":       a.CreatedAt,
			}},
			options.FindOneAndUpdate().SetUpsert(true).SetReturnDocument(options.After),
		).
		Decode(&stored)

	if err != nil {
		return Assessment{}, fmt.Errorf("mongostore: put assessment: %w", err)
	}
	return stored, nil
}

// GetAssessmentByFingerprint returns the stored verdict for a URL fingerprint,
// fresh or not.
//
// Callers that intend to *serve* the result must additionally check IsFresh;
// this method reports what is stored, not what is currently true.
func (s *Store) GetAssessmentByFingerprint(ctx context.Context, fingerprint string) (Assessment, error) {
	if s == nil || s.db == nil {
		return Assessment{}, ErrClosed
	}

	var a Assessment
	err := s.db.Collection(CollectionAssessments).
		FindOne(ctx, bson.M{"_id": fingerprint}).
		Decode(&a)

	switch {
	case err == nil:
		return a, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Assessment{}, ErrAssessmentNotFound
	default:
		return Assessment{}, fmt.Errorf("mongostore: get assessment: %w", err)
	}
}

// FindFreshAssessment returns a verdict only if it is still current at now.
//
// This is the read the hot path uses, and the freshness rule lives here so that
// no caller can forget it. An expired verdict is reported as not found, which
// makes "stale" and "absent" behave identically to every caller.
func (s *Store) FindFreshAssessment(ctx context.Context, fingerprint string, now time.Time) (Assessment, error) {
	a, err := s.GetAssessmentByFingerprint(ctx, fingerprint)
	if err != nil {
		return Assessment{}, err
	}
	if !a.IsFresh(now) {
		return Assessment{}, ErrAssessmentNotFound
	}
	return a, nil
}

// GetAssessmentByScanID returns the verdict produced by a scan.
func (s *Store) GetAssessmentByScanID(ctx context.Context, scanID string) (Assessment, error) {
	if s == nil || s.db == nil {
		return Assessment{}, ErrClosed
	}

	var a Assessment
	err := s.db.Collection(CollectionAssessments).
		FindOne(ctx, bson.M{"scan_id": scanID}).
		Decode(&a)

	switch {
	case err == nil:
		return a, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Assessment{}, ErrAssessmentNotFound
	default:
		return Assessment{}, fmt.Errorf("mongostore: get assessment by scan: %w", err)
	}
}

// ExpireAssessment removes a stored verdict so the next request re-analyses.
//
// This is explicit deletion rather than waiting for the TTL index, because the
// TTL monitor runs roughly once a minute and callers need the cache miss to
// happen now.
func (s *Store) ExpireAssessment(ctx context.Context, fingerprint string) error {
	if s == nil || s.db == nil {
		return ErrClosed
	}

	_, err := s.db.Collection(CollectionAssessments).DeleteOne(ctx, bson.M{"_id": fingerprint})
	if err != nil {
		return fmt.Errorf("mongostore: expire assessment: %w", err)
	}
	return nil
}

// DeleteExpiredAssessments removes every verdict whose expiry has passed.
//
// It is a belt-and-braces cleanup for records the TTL monitor has not reached
// yet. It returns the number deleted.
func (s *Store) DeleteExpiredAssessments(ctx context.Context, now time.Time) (int64, error) {
	if s == nil || s.db == nil {
		return 0, ErrClosed
	}

	res, err := s.db.Collection(CollectionAssessments).
		DeleteMany(ctx, bson.M{"expires_at": bson.D{{Key: "$lte", Value: now}}})
	if err != nil {
		return 0, fmt.Errorf("mongostore: delete expired assessments: %w", err)
	}
	return res.DeletedCount, nil
}

// ExpiredAssessments returns stale verdicts without deleting them, so the
// lifecycle can move the owning scan to ScanExpired.
func (s *Store) ExpiredAssessments(ctx context.Context, now time.Time, limit int64) ([]Assessment, error) {
	if s == nil || s.db == nil {
		return nil, ErrClosed
	}
	if limit <= 0 {
		limit = 100
	}

	cursor, err := s.db.Collection(CollectionAssessments).Find(ctx,
		bson.M{"expires_at": bson.D{{Key: "$lte", Value: now}}},
		options.Find().SetLimit(limit),
	)
	if err != nil {
		return nil, fmt.Errorf("mongostore: find expired assessments: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var out []Assessment
	if err := cursor.All(ctx, &out); err != nil {
		return nil, fmt.Errorf("mongostore: decode expired assessments: %w", err)
	}
	return out, nil
}
