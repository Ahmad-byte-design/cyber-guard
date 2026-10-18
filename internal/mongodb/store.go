package mongodb

import (
	"context"
	"fmt"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"cyberguard/internal/models"
)

// Store is the persistence layer for URL assessments.
//
// One collection. Three query patterns, each backed by an index created in
// EnsureIndexes:
//
//   - cache lookup by canonical URL (urlHash) — the check-url fast path;
//   - one writable record per canonical URL (unique partial index), so
//     concurrent equivalent requests converge on one provider submission;
//   - get-all, newest first by updatedAt, so a record that just obtained its
//     final result sorts near the top.
//
// Completed results are protected by every write path here: an update that
// would move a record backward — pending data over a finished assessment —
// simply does not match and reports `matched: false`.
type Store struct {
	coll *mongo.Collection
}

// NewStore builds a Store over one collection of a connected database.
func NewStore(db *mongo.Database, name string) *Store {
	return &Store{coll: db.Collection(name)}
}

// EnsureIndexes creates the indexes the queries here rely on. It is
// idempotent: MongoDB treats an identical existing index as a no-op.
func (s *Store) EnsureIndexes(ctx context.Context) error {
	for _, model := range []mongo.IndexModel{
		{
			// get-all sorts on every call.
			Keys:    bson.D{{Key: "updatedAt", Value: -1}},
			Options: options.Index().SetName("by_updated_at"),
		},
		{
			// One record per canonical URL. The partial filter keeps
			// records written before URL hashing existed out of the
			// unique index; they are adopted into it on first touch.
			Keys: bson.D{{Key: "urlHash", Value: 1}},
			Options: options.Index().SetName("uniq_url_hash").SetUnique(true).
				SetPartialFilterExpression(bson.M{"urlHash": bson.M{"$exists": true}}),
		},
	} {
		if _, err := s.coll.Indexes().CreateOne(ctx, model); err != nil {
			return fmt.Errorf("mongodb: create indexes: %w", err)
		}
	}
	return nil
}

// FindByURLHash returns the record holding the canonical URL hash, or nil
// with a nil error when no record exists yet.
func (s *Store) FindByURLHash(ctx context.Context, urlHash string) (*models.Submission, error) {
	var sub models.Submission
	err := s.coll.FindOne(ctx, bson.M{"urlHash": urlHash}).Decode(&sub)
	switch {
	case err == nil:
		return &sub, nil
	case err == mongo.ErrNoDocuments:
		return nil, nil
	default:
		return nil, fmt.Errorf("mongodb: find submission by url hash: %w", err)
	}
}

// FindByRawURL returns a record stored before URL hashing existed that holds
// exactly the given URL. Records that were already adopted carry a urlHash and
// are found by FindByURLHash instead, so this stays a one-time fallback.
func (s *Store) FindByRawURL(ctx context.Context, url string) (*models.Submission, error) {
	var sub models.Submission
	err := s.coll.FindOne(ctx, bson.M{
		"url":     url,
		"urlHash": bson.M{"$exists": false},
	}).Decode(&sub)
	switch {
	case err == nil:
		return &sub, nil
	case err == mongo.ErrNoDocuments:
		return nil, nil
	default:
		return nil, fmt.Errorf("mongodb: find unhashed submission: %w", err)
	}
}

// AdoptURLHash backfills the canonical URL hash onto a legacy record so
// subsequent lookups go through the index. It reports whether it acted;
// false means another request adopted the record first.
func (s *Store) AdoptURLHash(ctx context.Context, id bson.ObjectID, urlHash string) (bool, error) {
	res, err := s.coll.UpdateOne(ctx,
		bson.M{"_id": id, "urlHash": bson.M{"$exists": false}},
		bson.M{"$set": bson.M{"urlHash": urlHash}},
	)
	if err != nil {
		return false, fmt.Errorf("mongodb: adopt url hash: %w", err)
	}
	return res.MatchedCount == 1, nil
}

// InsertSubmission stores one submission and sets its ID.
//
// A unique-index violation (a concurrent request stored the same canonical
// URL first) is returned unwrapped so callers can distinguish it with
// mongo.IsDuplicateKeyError and reuse the winner's record.
func (s *Store) InsertSubmission(ctx context.Context, sub *models.Submission) error {
	res, err := s.coll.InsertOne(ctx, sub)
	if err != nil {
		return fmt.Errorf("mongodb: insert submission: %w", err)
	}
	if id, ok := res.InsertedID.(bson.ObjectID); ok {
		sub.ID = id
	}
	return nil
}

// SavePendingProgress updates a pending record with the provider's latest
// incomplete data, and reports whether the record was still pending.
//
// Scanner fields the provider did not send are left as they were, so partial
// snapshots cannot erase earlier progress. It can never touch a completed
// assessment.
func (s *Store) SavePendingProgress(ctx context.Context, id bson.ObjectID, stage *models.Submission) (bool, error) {
	set := bson.M{
		"status":    models.StatusPending,
		"finished":  false,
		"updatedAt": stage.UpdatedAt,
	}
	if stage.SHA256 != "" {
		set["sha256"] = stage.SHA256
	}
	if stage.Scanners != nil {
		set["scanners"] = stage.Scanners
	}
	if len(stage.ScannersV2) > 0 {
		set["scannersV2"] = stage.ScannersV2
	}
	if stage.Reports != nil {
		set["reports"] = stage.Reports
	}
	return s.updateGuarded(ctx, id, set, "save pending progress")
}

// SaveFinalResult marks a pending record completed with the provider's
// finished data and reports whether it won the write.
//
// `matched: false` means a completed record existed and was left alone —
// another request may have saved the same final result moments earlier.
func (s *Store) SaveFinalResult(ctx context.Context, id bson.ObjectID, final *models.Submission) (bool, error) {
	set := bson.M{
		"sha256":     final.SHA256,
		"scanType":   final.ScanType,
		"status":     models.StatusCompleted,
		"finished":   true,
		"scanners":   final.Scanners,
		"scannersV2": final.ScannersV2,
		"reports":    final.Reports,
		"verdict":    final.Verdict,
		"updatedAt":  final.UpdatedAt,
	}
	return s.updateGuarded(ctx, id, set, "save final result")
}

// ResetForRescan clears a record that must be analysed again — a pending
// record past its usable lifetime, or a completed record past the cache
// lifetime — and points it at a fresh provider submission. It reports whether
// the reset happened.
//
// The guard keeps the reset from racing a record another request just
// completed or reset: `matched: false` means the caller must re-read the
// record and honour what it now holds.
func (s *Store) ResetForRescan(ctx context.Context, id bson.ObjectID, expiredBefore time.Time, stage *models.Submission) (bool, error) {
	filter := bson.M{
		"_id": id,
		"$or": bson.A{
			bson.M{"status": bson.M{"$ne": models.StatusCompleted}},
			bson.M{"status": models.StatusCompleted, "updatedAt": bson.M{"$lt": expiredBefore}},
		},
	}
	set := bson.M{
		"providerId": stage.ProviderID,
		"sha256":     "",
		"scanType":   stage.ScanType,
		"status":     models.StatusPending,
		"finished":   false,
		"verdict":    nil,
		"scanners":   nil,
		"scannersV2": nil,
		"reports":    nil,
		"updatedAt":  stage.UpdatedAt,
	}
	res, err := s.coll.UpdateOne(ctx, filter, bson.M{"$set": set})
	if err != nil {
		return false, fmt.Errorf("mongodb: reset for rescan: %w", err)
	}
	return res.MatchedCount == 1, nil
}

// ListSubmissions returns one page of assessments, newest first by updatedAt,
// and the total count of stored assessments.
//
// An empty collection returns an empty slice and a zero total; that is a
// normal result, not an error.
func (s *Store) ListSubmissions(ctx context.Context, page, limit int) ([]models.Submission, int64, error) {
	total, err := s.coll.CountDocuments(ctx, bson.D{})
	if err != nil {
		return nil, 0, fmt.Errorf("mongodb: count submissions: %w", err)
	}

	skip := int64(page-1) * int64(limit)
	findOpts := options.Find().
		// Newest first. The by_updated_at index serves this sort.
		SetSort(bson.D{{Key: "updatedAt", Value: -1}}).
		SetSkip(skip).
		SetLimit(int64(limit))

	cursor, err := s.coll.Find(ctx, bson.D{}, findOpts)
	if err != nil {
		return nil, 0, fmt.Errorf("mongodb: list submissions: %w", err)
	}
	defer cursor.Close(ctx)

	var items = make([]models.Submission, 0)
	if err := cursor.All(ctx, &items); err != nil {
		return nil, 0, fmt.Errorf("mongodb: decode submissions: %w", err)
	}
	return items, total, nil
}

// updateGuarded applies $set to one record, but only while it is not
// completed — the single guard every partial write shares.
func (s *Store) updateGuarded(ctx context.Context, id bson.ObjectID, set bson.M, op string) (bool, error) {
	res, err := s.coll.UpdateOne(ctx,
		bson.M{"_id": id, "status": bson.M{"$ne": models.StatusCompleted}},
		bson.M{"$set": set},
	)
	if err != nil {
		return false, fmt.Errorf("mongodb: %s: %w", op, err)
	}
	return res.MatchedCount == 1, nil
}
