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

// ErrDuplicateScan is returned by CreateScan only through the created flag; it
// exists so callers that need to distinguish the two outcomes by error can.
var ErrDuplicateScan = errors.New("mongostore: an active scan already exists for this URL")

// CreateScan inserts a new scan, or returns the active scan that already exists
// for the same URL fingerprint.
//
// The second return value reports whether this call created the document. It
// is the signal that governs whether a job may be enqueued: only a caller that
// created the scan may enqueue, or N concurrent requests would produce N
// provider submissions for one URL.
//
// Dedup is enforced by the partial unique index on url_fingerprint for active
// statuses, not by a read-then-write check. A check would be a TOCTOU race:
// two concurrent requests could both see "no active scan" and both insert. The
// database rejects the loser with a duplicate-key error, which this method
// turns into "here is the winner's scan, do not enqueue".
func (s *Store) CreateScan(ctx context.Context, scan Scan) (Scan, bool, error) {
	if s == nil || s.db == nil {
		return Scan{}, false, ErrClosed
	}
	if scan.ScanID == "" {
		return Scan{}, false, errors.New("mongostore: ScanID is required")
	}
	if scan.URLFingerprint == "" {
		return Scan{}, false, errors.New("mongostore: URLFingerprint is required")
	}
	if scan.Status == "" {
		scan.Status = ScanQueued
	}
	if !scan.Status.Valid() {
		return Scan{}, false, fmt.Errorf("mongostore: invalid status %q", scan.Status)
	}
	if scan.CreatedAt.IsZero() {
		scan.CreatedAt = time.Now().UTC()
	}
	if scan.UpdatedAt.IsZero() {
		scan.UpdatedAt = scan.CreatedAt
	}
	// A new scan is work immediately, so it is due now.
	//
	// Setting it here rather than relying on "absent means due" is deliberate:
	// the claim query has to tolerate an absent available_at anyway, for scans
	// written before these fields existed, and a query that does two things is
	// harder to reason about than a query that does one.
	if scan.AvailableAt == nil && scan.Status == ScanQueued {
		scan.AvailableAt = &scan.CreatedAt
	}

	coll := s.db.Collection(CollectionScans)
	_, err := coll.InsertOne(ctx, scan)
	if err == nil {
		return scan, true, nil
	}

	if !mongo.IsDuplicateKeyError(err) {
		return Scan{}, false, fmt.Errorf("mongostore: insert scan: %w", err)
	}

	// A duplicate is expected here and is the normal outcome under
	// concurrency, so it is not logged as an error.
	existing, findErr := s.FindActiveScanByFingerprint(ctx, scan.URLFingerprint)
	if findErr != nil {
		// The winner finished between our insert failing and this lookup, or
		// the document is otherwise gone. Report the duplicate rather than a
		// confusing lookup error; the caller will re-evaluate.
		return Scan{}, false, ErrDuplicateScan
	}
	return existing, false, nil
}

// GetScan returns a scan by its identifier.
func (s *Store) GetScan(ctx context.Context, scanID string) (Scan, error) {
	if s == nil || s.db == nil {
		return Scan{}, ErrClosed
	}

	var scan Scan
	err := s.db.Collection(CollectionScans).
		FindOne(ctx, bson.M{"_id": scanID}).
		Decode(&scan)

	switch {
	case err == nil:
		return scan, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Scan{}, ErrScanNotFound
	default:
		return Scan{}, fmt.Errorf("mongostore: get scan: %w", err)
	}
}

// ErrScanNotFound is returned when no document matches.
var ErrScanNotFound = errors.New("mongostore: scan not found")

// FindActiveScanByFingerprint returns the queued or running scan for a URL
// fingerprint, if one exists.
//
// This is a read, so it is advisory: it narrows a race but does not close one.
// CreateScan is what closes it.
func (s *Store) FindActiveScanByFingerprint(ctx context.Context, fingerprint string) (Scan, error) {
	if s == nil || s.db == nil {
		return Scan{}, ErrClosed
	}

	var scan Scan
	err := s.db.Collection(CollectionScans).
		FindOne(ctx, bson.M{
			"url_fingerprint": fingerprint,
			"status":          bson.D{{Key: "$in", Value: activeStatuses}},
		}).
		Decode(&scan)

	switch {
	case err == nil:
		return scan, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Scan{}, ErrScanNotFound
	default:
		return Scan{}, fmt.Errorf("mongostore: find active scan: %w", err)
	}
}

// FindLatestScanByFingerprint returns the most recently created scan for a URL
// fingerprint, in any status.
//
// It backs `POST /api/v1/get-url`, which answers "what happened to this URL"
// without the caller having kept a scan ID.
//
// The newest scan is returned rather than the newest *completed* one. A caller
// asking about a URL right now wants the current state of that URL, and
// preferring an older completed scan over a newer in-flight one would report a
// verdict as the answer while a fresh analysis of the same URL is still
// running. It also keeps the rule simple enough to state in one sentence.
//
// Scans accumulate per fingerprint across freshness windows, so this needs an
// index that is not the partial active-scan one; see idxScansFingerprintRecent.
func (s *Store) FindLatestScanByFingerprint(ctx context.Context, fingerprint string) (Scan, error) {
	if s == nil || s.db == nil {
		return Scan{}, ErrClosed
	}
	if fingerprint == "" {
		return Scan{}, ErrScanNotFound
	}

	var scan Scan
	err := s.db.Collection(CollectionScans).
		FindOne(ctx,
			bson.M{"url_fingerprint": fingerprint},
			options.FindOne().SetSort(bson.D{{Key: "created_at", Value: -1}}),
		).
		Decode(&scan)

	switch {
	case err == nil:
		return scan, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Scan{}, ErrScanNotFound
	default:
		return Scan{}, fmt.Errorf("mongostore: find latest scan: %w", err)
	}
}

// UpdateScanStatus advances a scan's lifecycle state and stamps the
// corresponding timestamp.
//
// Status transitions are not validated here. The scan lifecycle belongs to the
// worker in Phase 4, and encoding a transition table in the repository would
// duplicate that rule in two places, where the two copies would drift.
//
// The one invariant this does enforce is that a verdict can never be written
// onto a non-completed scan, because there is no field for one: verdicts live
// in the assessments collection, and a document there can only be created for a
// completed scan.
func (s *Store) UpdateScanStatus(
	ctx context.Context,
	scanID string,
	status ScanStatus,
	lastErrorCode string,
) (Scan, error) {
	if s == nil || s.db == nil {
		return Scan{}, ErrClosed
	}
	if !status.Valid() {
		return Scan{}, fmt.Errorf("mongostore: invalid status %q", status)
	}

	now := time.Now().UTC()
	set := bson.M{
		"status":     status,
		"updated_at": now,
	}
	if lastErrorCode != "" {
		set["last_error_code"] = lastErrorCode
	}

	switch status {
	case ScanRunning:
		// Set once, on first claim; a retry must not overwrite the original.
		set["started_at"] = now
	case ScanCompleted, ScanFailed, ScanTimedOut, ScanExpired:
		set["completed_at"] = now
	}

	update := bson.M{
		"$set": set,
		// Clear the error code when a scan starts succeeding again, so a stale
		// failure reason cannot outlive the failure.
		"$unset": bson.M{},
	}
	if lastErrorCode == "" && status.IsActive() {
		update["$unset"] = bson.M{"last_error_code": ""}
	}

	var scan Scan
	err := s.db.Collection(CollectionScans).
		FindOneAndUpdate(ctx, bson.M{"_id": scanID}, update,
			options.FindOneAndUpdate().SetReturnDocument(options.After)).
		Decode(&scan)

	switch {
	case err == nil:
		return scan, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Scan{}, ErrScanNotFound
	default:
		return Scan{}, fmt.Errorf("mongostore: update scan status: %w", err)
	}
}

// RecordProviderSubmission persists the provider's job ID, submission ID,
// environment and current state, and stamps the submission time.
//
// It is called once per scan, immediately after the provider accepts the URL.
// Persisting the job ID is what lets a restarted worker resume polling instead
// of submitting the same URL again — the guarantee ADR 0013 depends on.
//
// It does not change the scan status: the worker owns the lifecycle, and a
// write here that also moved the status would make two components race over the
// same field.
func (s *Store) RecordProviderSubmission(
	ctx context.Context,
	scanID, provider, providerScanID, providerSubmissionID, providerState string,
	environmentID *int,
) (Scan, error) {
	if s == nil || s.db == nil {
		return Scan{}, ErrClosed
	}
	if providerScanID == "" {
		// Without a job ID there is nothing to resume from, and storing a
		// blank would defeat the purpose of the field.
		return Scan{}, errors.New("mongostore: providerScanID is required")
	}

	now := time.Now().UTC()
	set := bson.M{
		"provider":         provider,
		"provider_scan_id": providerScanID,
		"provider_state":   providerState,
		"submitted_at":     now,
		"updated_at":       now,
	}
	if providerSubmissionID != "" {
		set["provider_submission_id"] = providerSubmissionID
	}
	if environmentID != nil {
		set["provider_environment_id"] = environmentID
	}

	var scan Scan
	err := s.db.Collection(CollectionScans).
		FindOneAndUpdate(ctx, bson.M{"_id": scanID}, bson.M{"$set": set},
			options.FindOneAndUpdate().SetReturnDocument(options.After)).
		Decode(&scan)

	switch {
	case err == nil:
		return scan, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Scan{}, ErrScanNotFound
	default:
		return Scan{}, fmt.Errorf("mongostore: record provider submission: %w", err)
	}
}

// RecordProviderState updates the provider's reported state and error fields
// during polling, without touching the scan lifecycle status.
func (s *Store) RecordProviderState(
	ctx context.Context,
	scanID, providerState, errorType, errorOrigin string,
) (Scan, error) {
	if s == nil || s.db == nil {
		return Scan{}, ErrClosed
	}

	set := bson.M{"provider_state": providerState, "updated_at": time.Now().UTC()}
	if errorType != "" {
		set["provider_error_type"] = errorType
	}
	if errorOrigin != "" {
		set["provider_error_origin"] = errorOrigin
	}

	var scan Scan
	err := s.db.Collection(CollectionScans).
		FindOneAndUpdate(ctx, bson.M{"_id": scanID}, bson.M{"$set": set},
			options.FindOneAndUpdate().SetReturnDocument(options.After)).
		Decode(&scan)

	switch {
	case err == nil:
		return scan, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Scan{}, ErrScanNotFound
	default:
		return Scan{}, fmt.Errorf("mongostore: record provider state: %w", err)
	}
}

// IncrementAttempts bumps the attempt counter for a scan.
func (s *Store) IncrementAttempts(ctx context.Context, scanID string) (Scan, error) {
	if s == nil || s.db == nil {
		return Scan{}, ErrClosed
	}

	var scan Scan
	err := s.db.Collection(CollectionScans).
		FindOneAndUpdate(ctx, bson.M{"_id": scanID},
			bson.M{
				"$inc": bson.M{"attempts": 1},
				"$set": bson.M{"updated_at": time.Now().UTC()},
				"$max": bson.M{"last_attempt_at": time.Now().UTC()},
			},
			options.FindOneAndUpdate().SetReturnDocument(options.After)).
		Decode(&scan)

	switch {
	case err == nil:
		return scan, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Scan{}, ErrScanNotFound
	default:
		return Scan{}, fmt.Errorf("mongostore: increment attempts: %w", err)
	}
}

// FindActiveScanByProviderScanID lets a restarted worker find an in-flight
// submission by the provider job ID, so it can resume polling rather than
// submitting again.
func (s *Store) FindActiveScanByProviderScanID(ctx context.Context, providerScanID string) (Scan, error) {
	if s == nil || s.db == nil {
		return Scan{}, ErrClosed
	}

	var scan Scan
	err := s.db.Collection(CollectionScans).
		FindOne(ctx, bson.M{
			"provider_scan_id": providerScanID,
			"status":           bson.D{{Key: "$in", Value: activeStatuses}},
		}).
		Decode(&scan)

	switch {
	case err == nil:
		return scan, nil
	case errors.Is(err, mongo.ErrNoDocuments):
		return Scan{}, ErrScanNotFound
	default:
		return Scan{}, fmt.Errorf("mongostore: find scan by provider id: %w", err)
	}
}

// ListStalledScans returns active scans untouched since the given time, for
// job recovery after a worker crash.
//
// The query uses the by_status_updated index, so this stays cheap as the
// collection grows.
func (s *Store) ListStalledScans(ctx context.Context, olderThan time.Time, limit int64) ([]Scan, error) {
	if s == nil || s.db == nil {
		return nil, ErrClosed
	}
	if limit <= 0 {
		limit = 100
	}

	cursor, err := s.db.Collection(CollectionScans).Find(ctx,
		bson.M{
			"status":     bson.D{{Key: "$in", Value: activeStatuses}},
			"updated_at": bson.D{{Key: "$lt", Value: olderThan}},
		},
		options.Find().SetSort(bson.D{{Key: "updated_at", Value: 1}}).SetLimit(limit),
	)
	if err != nil {
		return nil, fmt.Errorf("mongostore: list stalled scans: %w", err)
	}
	defer func() { _ = cursor.Close(ctx) }()

	var scans []Scan
	if err := cursor.All(ctx, &scans); err != nil {
		return nil, fmt.Errorf("mongostore: decode stalled scans: %w", err)
	}
	return scans, nil
}

// RecordScanTarget stores or clears the bounded URL detail a scan needs while
// it is in flight.
//
// It exists so the detail can be captured at submission time — when the worker
// still holds the plaintext — and removed once the verdict is known and the
// assessment has been written. A separate clear is what keeps the long-lived
// audit trail from retaining a path fragment for every URL ever scanned.
//
// The query string is never accepted. The signature has no parameter for it.
func (s *Store) RecordScanTarget(ctx context.Context, scanID, scheme, port, pathPrefix string, clear bool) error {
	if s == nil || s.db == nil {
		return ErrClosed
	}
	if scanID == "" {
		return errors.New("mongostore: ScanID is required")
	}

	set := bson.M{"updated_at": time.Now().UTC()}
	if clear {
		set = bson.M{
			"updated_at":  time.Now().UTC(),
			"scheme":      "",
			"port":        "",
			"path_prefix": "",
		}
	} else {
		set["scheme"] = scheme
		set["port"] = port
		set["path_prefix"] = pathPrefix
	}

	_, err := s.db.Collection(CollectionScans).UpdateOne(ctx, bson.M{"_id": scanID}, bson.M{"$set": set})
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			return ErrScanNotFound
		}
		return fmt.Errorf("mongostore: record scan target: %w", err)
	}
	return nil
}
