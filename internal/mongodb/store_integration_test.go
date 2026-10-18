package mongodb

// These tests run against a real MongoDB and are skipped unless the caller
// points at one by setting MONGO_TEST_URI. They never contact the analysis
// provider; only the store's own behaviour is under test.
//
// Locally the compose MongoDB is already running and reachable from inside
// the `go` toolchain container, so the simplest invocation is:
//
//	docker compose run --rm \
//	  -e MONGO_TEST_URI=mongodb://mongodb:27017 \
//	  go go test -run TestStore ./internal/mongodb
//
// (127.0.0.1 works when the container joins the compose network too.)

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"

	"cyberguard/internal/models"
)

// TestStoreIntegration covers the store end to end against real MongoDB:
// index creation, insertion with a filled object ID, URL-hash lookup with the
// unique constraint, legacy adoption, guarded writes, and newest-first
// listing including the empty collection.
func TestStoreIntegration(t *testing.T) {
	ctx, store := openTestDatabase(t)

	if err := store.EnsureIndexes(ctx); err != nil {
		t.Fatalf("EnsureIndexes: %v", err)
	}
	// An identical second call is a no-op, not an error.
	if err := store.EnsureIndexes(ctx); err != nil {
		t.Fatalf("EnsureIndexes (second call): %v", err)
	}

	// --- empty collection ------------------------------------------------
	items, total, err := store.ListSubmissions(ctx, 1, 10)
	if err != nil {
		t.Fatalf("ListSubmissions (empty): %v", err)
	}
	if items == nil {
		t.Error("empty collection returned a nil slice, want an empty slice")
	}
	if len(items) != 0 || total != 0 {
		t.Errorf("empty collection: got len=%d total=%d, want 0/0", len(items), total)
	}

	// --- insert several, staggered so newest-first is unambiguous ----------
	now := time.Now().UTC()
	stamp := time.Now().UTC().Format("150405.000000000")
	inserted := make([]*models.Submission, 0, 5)
	for i := range 5 {
		urlx := "https://example.com/doc-" + stamp + "-" + string(rune('a'+i))
		sub := &models.Submission{
			URL:       urlx,
			URLHash:   storeHash(urlx),
			Provider:  models.ProviderName,
			ScanType:  "all",
			Status:    models.StatusPending,
			Verdict:   nil,
			CreatedAt: now.Add(-time.Duration(5-i) * time.Minute),
			UpdatedAt: now.Add(-time.Duration(5-i) * time.Minute),
		}
		if err := store.InsertSubmission(ctx, sub); err != nil {
			t.Fatalf("InsertSubmission %d: %v", i, err)
		}
		if !sub.ID.IsZero() {
			inserted = append(inserted, sub)
		} else {
			t.Errorf("InsertSubmission %d did not set the document ID", i)
		}
	}
	if len(inserted) != 5 {
		t.Fatalf("inserted %d documents, want 5", len(inserted))
	}

	// --- the unique index must refuse a duplicate canonical URL -----------
	dup := &models.Submission{
		URL: inserted[0].URL, URLHash: inserted[0].URLHash,
		Provider: models.ProviderName, ScanType: "all", Status: models.StatusPending,
	}
	err = store.InsertSubmission(ctx, dup)
	if err == nil {
		t.Fatal("a duplicate urlHash was accepted; the uniq_url_hash index is missing")
	}
	if !mongo.IsDuplicateKeyError(err) {
		t.Errorf("duplicate insert error = %v, want a duplicate-key error", err)
	}

	// --- lookup by URL hash ------------------------------------------------
	found, err := store.FindByURLHash(ctx, inserted[2].URLHash)
	if err != nil {
		t.Fatalf("FindByURLHash: %v", err)
	}
	if found == nil || found.ID != inserted[2].ID {
		t.Fatalf("FindByURLHash returned %+v, want document %s", found, inserted[2].ID.Hex())
	}
	missing, err := store.FindByURLHash(ctx, storeHash("https://example.com/never-stored"))
	if err != nil || missing != nil {
		t.Fatalf("unknown hash lookup = (%v, %v), want (nil, nil)", missing, err)
	}

	// --- legacy adoption -----------------------------------------------------
	legacyURL := "https://example.com/legacy-" + stamp
	legacy := &models.Submission{
		URL: legacyURL, Provider: models.ProviderName,
		// Deliberately no URLHash and a legacy status: an old record.
		ScanType: "all", Status: models.LegacyStatusSubmitted,
		CreatedAt: now, UpdatedAt: now,
	}
	if err := store.InsertSubmission(ctx, legacy); err != nil {
		t.Fatalf("InsertSubmission (legacy): %v", err)
	}
	legacyHash := storeHash(legacyURL)
	notFound, err := store.FindByURLHash(ctx, legacyHash)
	if err != nil || notFound != nil {
		t.Fatalf("hash lookup before adoption = (%v, %v), want (nil, nil)", notFound, err)
	}
	byURL, err := store.FindByRawURL(ctx, legacyURL)
	if err != nil || byURL == nil {
		t.Fatalf("FindByRawURL = (%v, %v), want the legacy record", byURL, err)
	}
	legacyID := byURL.ID
	adopted, err := store.AdoptURLHash(ctx, legacyID, legacyHash)
	if err != nil || !adopted {
		t.Fatalf("AdoptURLHash = (%v, %v), want (true, nil)", adopted, err)
	}
	// The second adoption is a no-op (another request was first).
	adopted, err = store.AdoptURLHash(ctx, legacyID, legacyHash)
	if err != nil || adopted {
		t.Errorf("double adoption = (%v, %v), want (false, nil)", adopted, err)
	}
	// And the lookup now goes through the hash.
	byHash, err := store.FindByURLHash(ctx, legacyHash)
	if err != nil || byHash == nil || byHash.ID != legacyID {
		t.Fatalf("hash lookup after adoption = (%+v, %v)", byHash, err)
	}
	if byHash.IsCompleted() {
		t.Error("a legacy 'submitted' record must still read as pending")
	}

	// --- pending progress: latest data persists, no verdict ----------------
	progress := &models.Submission{
		ID: inserted[0].ID, URL: inserted[0].URL, URLHash: inserted[0].URLHash,
		Provider: models.ProviderName, ProviderID: inserted[0].ProviderID,
		ScannersV2: map[string]any{"bfore_ai": map[string]any{"status": "clean", "progress": 30}},
		CreatedAt:  inserted[0].CreatedAt, UpdatedAt: now,
	}
	matched, err := store.SavePendingProgress(ctx, inserted[0].ID, progress)
	if err != nil || !matched {
		t.Fatalf("SavePendingProgress = (%v, %v), want (true, nil)", matched, err)
	}
	savedDoc, err := store.FindByURLHash(ctx, inserted[0].URLHash)
	if err != nil || savedDoc == nil {
		t.Fatalf("pending record lookup: (%v, %v)", savedDoc, err)
	}
	if savedDoc.Status != models.StatusPending || savedDoc.Finished {
		t.Errorf("pending record after progress = %+v", savedDoc)
	}
	if savedDoc.ScannersV2 == nil {
		t.Error("the partial provider data was not persisted")
	}

	// --- final save: completed verdict, in place -----------------------------
	verdict := models.VerdictNoThreat
	final := &models.Submission{
		ID: inserted[0].ID, URL: inserted[0].URL, URLHash: inserted[0].URLHash,
		Provider: models.ProviderName, ProviderID: inserted[0].ProviderID,
		ScanType:   "all",
		ScannersV2: map[string]any{"bfore_ai": map[string]any{"status": "clean", "progress": 100}},
		Verdict:    &verdict,
		CreatedAt:  inserted[0].CreatedAt, UpdatedAt: now,
	}
	matched, err = store.SaveFinalResult(ctx, inserted[0].ID, final)
	if err != nil || !matched {
		t.Fatalf("SaveFinalResult = (%v, %v), want (true, nil)", matched, err)
	}
	savedDoc, err = store.FindByURLHash(ctx, inserted[0].URLHash)
	if err != nil || savedDoc == nil {
		t.Fatalf("completed record lookup: (%v, %v)", savedDoc, err)
	}
	if !savedDoc.IsCompleted() || savedDoc.Verdict == nil || *savedDoc.Verdict != models.VerdictNoThreat || !savedDoc.Finished {
		t.Errorf("completed record = %+v", savedDoc)
	}

	// --- a completed result cannot be overwritten ----------------------------
	stale := &models.Submission{
		ID:  inserted[0].ID,
		URL: inserted[0].URL, URLHash: inserted[0].URLHash,
		Provider: models.ProviderName,
		// pretend the provider reported incomplete state again
		ScannersV2: map[string]any{"bfore_ai": map[string]any{"status": "in-queue", "progress": 1}},
		CreatedAt:  inserted[0].CreatedAt, UpdatedAt: now,
	}
	matched, err = store.SavePendingProgress(ctx, inserted[0].ID, stale)
	if err != nil {
		t.Fatalf("SavePendingProgress on completed: %v", err)
	}
	if matched {
		t.Error("a completed assessment was overwritten by pending data")
	}
	matched, err = store.SaveFinalResult(ctx, inserted[0].ID, &models.Submission{
		ID: inserted[0].ID, ScanType: "all", UpdatedAt: now,
	})
	if err != nil {
		t.Fatalf("SaveFinalResult on completed: %v", err)
	}
	if matched {
		t.Error("a completed assessment was overwritten by a second final save")
	}
	// The completed record is untouched.
	savedDoc, err = store.FindByURLHash(ctx, inserted[0].URLHash)
	if err != nil || savedDoc == nil {
		t.Fatalf("protected record lookup: (%v, %v)", savedDoc, err)
	}
	if savedDoc.Verdict == nil || *savedDoc.Verdict != models.VerdictNoThreat {
		t.Errorf("the protected verdict was altered: %v", savedDoc.Verdict)
	}

	// --- rescan reset: only past-its-lifetime records may be reset ----------
	fresh := &models.Submission{
		ID:         inserted[0].ID,
		ProviderID: "qs-new", ScanType: "all",
		UpdatedAt: now,
	}
	// completed and still inside the cache lifetime → refused
	matched, err = store.ResetForRescan(ctx, inserted[0].ID, now.Add(-time.Hour), fresh)
	if err != nil {
		t.Fatalf("ResetForRescan (fresh completed): %v", err)
	}
	if matched {
		t.Error("a completed record inside its cache lifetime was reset")
	}
	// completed and expired → allowed
	matched, err = store.ResetForRescan(ctx, inserted[0].ID, now.Add(time.Hour), fresh)
	if err != nil || !matched {
		t.Fatalf("ResetForRescan (expired completed) = (%v, %v), want (true, nil)", matched, err)
	}
	afterReset, err := store.FindByURLHash(ctx, inserted[0].URLHash)
	if err != nil || afterReset == nil {
		t.Fatalf("record after reset: (%v, %v)", afterReset, err)
	}
	if afterReset.IsCompleted() || afterReset.ProviderID != "qs-new" || afterReset.Verdict != nil {
		t.Errorf("record after reset = %+v, want a pending record pointed at the new scan", afterReset)
	}

	// The reset happened in place: no second record for that canonical URL.
	_, total, err = store.ListSubmissions(ctx, 1, 100)
	if err != nil {
		t.Fatalf("ListSubmissions count: %v", err)
	}
	if want := int64(len(inserted) + 1); total != want {
		t.Errorf("records = %d, want %d (a rescan reset must not create a second record)", total, want)
	}
}

// TestStoreIntegrationListOrder checks that get-all orders by updatedAt,
// which keeps a record that just obtained its final result near the top.
func TestStoreIntegrationListOrder(t *testing.T) {
	ctx, store := openTestDatabase(t)
	if err := store.EnsureIndexes(ctx); err != nil {
		t.Fatalf("EnsureIndexes: %v", err)
	}

	now := time.Now().UTC()
	stamp := time.Now().UTC().Format("150405.000000000")
	first := &models.Submission{
		URL: "https://order.example/first-" + stamp, URLHash: storeHash("https://order.example/first-" + stamp),
		Provider: models.ProviderName, ScanType: "all", Status: models.StatusPending,
		CreatedAt: now.Add(-time.Hour), UpdatedAt: now.Add(-time.Hour),
	}
	if err := store.InsertSubmission(ctx, first); err != nil {
		t.Fatal(err)
	}
	second := &models.Submission{
		URL: "https://order.example/second-" + stamp, URLHash: storeHash("https://order.example/second-" + stamp),
		Provider: models.ProviderName, ScanType: "all", Status: models.StatusPending,
		CreatedAt: now.Add(-2 * time.Hour), UpdatedAt: now.Add(-2 * time.Hour),
	}
	if err := store.InsertSubmission(ctx, second); err != nil {
		t.Fatal(err)
	}

	// As stored: the newer createdAt (first) is head even though second's
	// createdAt is older — updatedAt decides.
	items, total, err := store.ListSubmissions(ctx, 1, 10)
	if err != nil || total != 2 {
		t.Fatalf("list = (%v, %d, %v)", items, total, err)
	}
	if items[0].ID != first.ID {
		t.Errorf("list head = %s, want %s (newest updatedAt first)", items[0].ID.Hex(), first.ID.Hex())
	}

	// Progress the older record recently: it must surface to the top.
	progress := &models.Submission{
		ID: second.ID, URL: second.URL, URLHash: second.URLHash,
		Provider: models.ProviderName, ProviderID: "qs-bump",
		CreatedAt: second.CreatedAt, UpdatedAt: now,
	}
	if matched, err := store.SavePendingProgress(ctx, second.ID, progress); err != nil || !matched {
		t.Fatalf("SavePendingProgress = (%v, %v)", matched, err)
	}
	items, _, err = store.ListSubmissions(ctx, 1, 10)
	if err != nil {
		t.Fatal(err)
	}
	if items[0].ID != second.ID {
		t.Errorf("list head = %s, want the recently-updated record %s", items[0].ID.Hex(), second.ID.Hex())
	}
}

func openTestDatabase(t *testing.T) (context.Context, *Store) {
	t.Helper()
	uri := os.Getenv("MONGO_TEST_URI")
	if uri == "" {
		t.Skip("MONGO_TEST_URI not set; skipping MongoDB integration test")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)

	client, err := mongo.Connect(options.Client().ApplyURI(uri).SetAppName("cyberguard-it"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := client.Ping(ctx, readpref.Primary()); err != nil {
		_ = client.Disconnect(context.Background())
		t.Fatalf("ping %s: %v", uri, err)
	}
	t.Cleanup(func() {
		dc, dcCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dcCancel()
		_ = client.Disconnect(dc)
	})

	// A fresh database per run, so parallel CI jobs cannot see each other's
	// data and a failed run cannot poison the next one.
	db := client.Database(uniqueDatabaseName())
	t.Cleanup(func() {
		dropCtx, dropCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer dropCancel()
		_ = db.Drop(dropCtx)
	})

	return ctx, NewStore(db, models.SubmissionCollection)
}

// storeHash mirrors the service's canonical URL key (hex SHA-256 of the URL
// bytes) so the integration data satisfies exactly what the index expects.
func storeHash(url string) string {
	digest := sha256.Sum256([]byte(url))
	return hex.EncodeToString(digest[:])
}

// uniqueDatabaseName produces a database name that cannot collide with a
// concurrent run or a stale leftover on the same server. MongoDB forbids
// dots in database names, so the fractional stamp uses an underscore.
func uniqueDatabaseName() string {
	return "cyberguard_it_" + time.Now().UTC().Format("20060102150405_000000000")
}
