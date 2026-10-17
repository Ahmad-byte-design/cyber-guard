//go:build integration

package mongostore_test

import (
	"context"
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"

	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/verdicts"
)

// testAEAD is a throwaway cipher. Its key protects nothing.
func testAEAD(t *testing.T) cipher.AEAD {
	t.Helper()
	aead, err := mongostore.NewTransientURLCipher([]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatalf("NewTransientURLCipher: %v", err)
	}
	return aead
}

// These tests run against the Compose MongoDB service:
//
//	docker compose up -d mongodb
//	docker compose run --rm go go test -tags integration ./internal/platform/mongostore/...
//
// Each test gets its own database so they can run in any order and leave no
// state behind.

// testDB creates an isolated database for one test and drops it afterwards.
func testDB(t *testing.T) *mongostore.Store {
	t.Helper()

	uri := envOr("MONGODB_URI", "mongodb://mongodb:27017")
	// MongoDB caps a namespace at 63 bytes, and test names here are long, so
	// the readable prefix is truncated and uniqueness comes from the suffix.
	sanitised := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			return r
		default:
			return '_'
		}
	}, t.Name())
	if len(sanitised) > 32 {
		sanitised = sanitised[:32]
	}
	dbName := fmt.Sprintf("cg_it_%s_%d", sanitised, time.Now().UnixNano()%1e9)

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	store, err := mongostore.Connect(ctx, mongostore.Options{
		URI:            uri,
		Database:       dbName,
		ConnectTimeout: 10 * time.Second,
		PingTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	t.Cleanup(func() {
		dctx, dcancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer dcancel()
		_ = store.Database().Drop(dctx)
		_ = store.Disconnect(dctx)
	})

	if err := store.EnsureIndexes(ctx); err != nil {
		t.Fatalf("EnsureIndexes: %v", err)
	}
	return store
}

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

func newScan(id, fingerprint string) mongostore.Scan {
	return mongostore.Scan{
		ScanID:            id,
		URLFingerprint:    fingerprint,
		Status:            mongostore.ScanQueued,
		MaxAttempts:       3,
		Hostname:          "example.test",
		RegistrableDomain: "example.test",
	}
}

// ---------------------------------------------------------------- indexes

func TestEnsureIndexesIsIdempotent(t *testing.T) {
	store := testDB(t)

	ctx := t.Context()
	for i := 0; i < 3; i++ {
		if err := store.EnsureIndexes(ctx); err != nil {
			t.Fatalf("EnsureIndexes run %d: %v", i+1, err)
		}
	}
}

func TestIndexesAreCreatedAsExpected(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	scans, err := store.ListIndexes(ctx, mongostore.CollectionScans)
	if err != nil {
		t.Fatalf("ListIndexes(scans): %v", err)
	}

	var sawActive, sawStatus, sawProvider bool
	for _, idx := range scans {
		switch idx["name"] {
		case "uniq_active_scan":
			sawActive = true
			if unique, _ := idx["unique"].(bool); !unique {
				t.Error("uniq_active_scan is not unique")
			}
			if idx["partialFilterExpression"] == nil {
				t.Error("uniq_active_scan is not partial; it would block history for one URL")
			}
		case "by_status_updated":
			sawStatus = true
		case "by_provider_scan_id":
			sawProvider = true
		}
	}
	if !sawActive || !sawStatus || !sawProvider {
		t.Errorf("scans indexes missing: active=%v status=%v provider=%v", sawActive, sawStatus, sawProvider)
	}

	assessments, err := store.ListIndexes(ctx, mongostore.CollectionAssessments)
	if err != nil {
		t.Fatalf("ListIndexes(assessments): %v", err)
	}
	var sawTTL bool
	for _, idx := range assessments {
		if idx["name"] == "ttl_expires_at" {
			sawTTL = true
			// A missing _id index is impossible; this is about the TTL itself.
			if _, ok := idx["expireAfterSeconds"]; !ok {
				t.Error("ttl_expires_at has no expireAfterSeconds")
			}
		}
	}
	if !sawTTL {
		t.Error("assessments is missing the TTL index")
	}
}

// scans must have no TTL: a scan is the audit trail for a provider submission
// and its lifecycle expiry is logical, not physical.
func TestScansHaveNoTTLIndex(t *testing.T) {
	store := testDB(t)

	idx, err := store.ListIndexes(t.Context(), mongostore.CollectionScans)
	if err != nil {
		t.Fatalf("ListIndexes: %v", err)
	}
	for _, i := range idx {
		if _, ok := i["expireAfterSeconds"]; ok {
			t.Errorf("scans has a TTL index %v; scan history must not be auto-deleted", i["name"])
		}
	}
}

// --------------------------------------------------------- scan lifecycle

func TestCreateScanAndGet(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	created, isNew, err := store.CreateScan(ctx, newScan("scan_1", "fp_1"))
	if err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if !isNew {
		t.Error("first CreateScan reported created=false")
	}
	if created.Status != mongostore.ScanQueued {
		t.Errorf("status = %q, want queued", created.Status)
	}
	if created.CreatedAt.IsZero() {
		t.Error("CreatedAt was not stamped")
	}

	got, err := store.GetScan(ctx, "scan_1")
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if got.URLFingerprint != "fp_1" {
		t.Errorf("fingerprint = %q", got.URLFingerprint)
	}
}

func TestGetScanMissingReturnsNotFound(t *testing.T) {
	store := testDB(t)

	if _, err := store.GetScan(t.Context(), "nope"); !errors.Is(err, mongostore.ErrScanNotFound) {
		t.Errorf("error = %v, want ErrScanNotFound", err)
	}
}

func TestCreateScanRejectsInvalidInput(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, _, err := store.CreateScan(ctx, mongostore.Scan{URLFingerprint: "fp"}); err == nil {
		t.Error("a scan with no ScanID was accepted")
	}
	if _, _, err := store.CreateScan(ctx, mongostore.Scan{ScanID: "s"}); err == nil {
		t.Error("a scan with no fingerprint was accepted")
	}
	bad := newScan("s2", "fp")
	bad.Status = "banana"
	if _, _, err := store.CreateScan(ctx, bad); err == nil {
		t.Error("a scan with an undefined status was accepted")
	}
}

// ------------------------------------------------- the dedup guarantee

// Sequential duplicate: the second call must not create a document.
func TestDuplicateScanIsRejected(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, created, err := store.CreateScan(ctx, newScan("scan_a", "fp_1")); err != nil || !created {
		t.Fatalf("first CreateScan: created=%v err=%v", created, err)
	}

	got, created, err := store.CreateScan(ctx, newScan("scan_b", "fp_1"))
	if err != nil {
		t.Fatalf("second CreateScan: %v", err)
	}
	if created {
		t.Error("second CreateScan reported created=true for a duplicate fingerprint")
	}
	if got.ScanID != "scan_a" {
		t.Errorf("returned scan %q, want the existing scan_a", got.ScanID)
	}
}

// This is the guarantee that prevents N concurrent requests producing N
// provider submissions for one URL. Only one goroutine may report created=true.
func TestConcurrentDuplicateScansProduceExactlyOneWinner(t *testing.T) {
	store := testDB(t)

	const goroutines = 50

	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners []string
		scanIDs = make(map[string]int)
	)

	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func(i int) {
			defer wg.Done()
			scanID := fmt.Sprintf("scan_%02d", i)

			got, created, err := store.CreateScan(t.Context(), newScan(scanID, "fp_race"))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				t.Errorf("CreateScan(%s): %v", scanID, err)
				return
			}
			if created {
				winners = append(winners, scanID)
			}
			scanIDs[got.ScanID]++
		}(i)
	}
	wg.Wait()

	if len(winners) != 1 {
		t.Fatalf("%d goroutines reported created=true, want exactly 1", len(winners))
	}

	// Every loser must have been handed the winner's scan ID, so every client
	// polls something that will actually complete.
	winner := winners[0]
	if scanIDs[winner] != goroutines {
		t.Errorf("winner %q returned to %d clients, want all %d", winner, scanIDs[winner], goroutines)
	}

	// And exactly one document exists.
	count, err := store.Database().
		Collection(mongostore.CollectionScans).
		CountDocuments(t.Context(), bson.M{"url_fingerprint": "fp_race"})
	if err != nil {
		t.Fatalf("CountDocuments: %v", err)
	}
	if count != 1 {
		t.Errorf("%d scan documents exist for one fingerprint, want 1", count)
	}
}

// History must accumulate: the partial index must not block a second scan once
// the first has finished.
func TestTerminalScansDoNotBlockHistory(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, _, err := store.CreateScan(ctx, newScan("scan_1", "fp_1")); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if _, err := store.UpdateScanStatus(ctx, "scan_1", mongostore.ScanCompleted, ""); err != nil {
		t.Fatalf("UpdateScanStatus: %v", err)
	}

	if _, created, err := store.CreateScan(ctx, newScan("scan_2", "fp_1")); err != nil || !created {
		t.Errorf("a new scan after completion was blocked: created=%v err=%v", created, err)
	}
}

// --------------------------------------------------- status transitions

func TestUpdateScanStatusStampsTimestamps(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, _, err := store.CreateScan(ctx, newScan("scan_1", "fp_1")); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	running, err := store.UpdateScanStatus(ctx, "scan_1", mongostore.ScanRunning, "")
	if err != nil {
		t.Fatalf("to running: %v", err)
	}
	if running.StartedAt == nil {
		t.Error("StartedAt not stamped on running")
	}
	if running.CompletedAt != nil {
		t.Error("CompletedAt stamped too early")
	}

	done, err := store.UpdateScanStatus(ctx, "scan_1", mongostore.ScanFailed, "provider_auth_failed")
	if err != nil {
		t.Fatalf("to failed: %v", err)
	}
	if done.CompletedAt == nil {
		t.Error("CompletedAt not stamped on failure")
	}
	if done.LastErrorCode != "provider_auth_failed" {
		t.Errorf("LastErrorCode = %q", done.LastErrorCode)
	}
	if done.Status.IsActive() {
		t.Error("a failed scan still reports IsActive")
	}
}

func TestUpdateScanStatusRejectsInvalidStatus(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, _, err := store.CreateScan(ctx, newScan("scan_1", "fp_1")); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if _, err := store.UpdateScanStatus(ctx, "scan_1", "nonsense", ""); err == nil {
		t.Error("an undefined status was accepted")
	}
	if _, err := store.UpdateScanStatus(ctx, "scan_missing", mongostore.ScanRunning, ""); !errors.Is(err, mongostore.ErrScanNotFound) {
		t.Errorf("error = %v, want ErrScanNotFound", err)
	}
}

// ------------------------------------------ provider submission metadata

func TestRecordProviderSubmissionPersistsBothIdentifiers(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, _, err := store.CreateScan(ctx, newScan("scan_1", "fp_1")); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	env := 140

	got, err := store.RecordProviderSubmission(ctx, "scan_1", "hybrid-analysis", "job-123", "sub-456", "IN_QUEUE", &env)
	if err != nil {
		t.Fatalf("RecordProviderSubmission: %v", err)
	}

	if got.ProviderScanID != "job-123" {
		t.Errorf("provider_scan_id = %q, want the job ID", got.ProviderScanID)
	}
	if got.ProviderSubmissionID != "sub-456" {
		t.Errorf("provider_submission_id = %q, want the submission ID", got.ProviderSubmissionID)
	}
	if got.SubmittedAt == nil {
		t.Error("submitted_at not stamped")
	}
	if got.ProviderEnvironmentID == nil || *got.ProviderEnvironmentID != 140 {
		t.Error("provider_environment_id not persisted")
	}

	// A restarted worker must be able to find it again.
	byProvider, err := store.FindActiveScanByProviderScanID(ctx, "job-123")
	if err != nil {
		t.Fatalf("FindActiveScanByProviderScanID: %v", err)
	}
	if byProvider.ScanID != "scan_1" {
		t.Errorf("found scan %q, want scan_1", byProvider.ScanID)
	}
}

func TestRecordProviderSubmissionRequiresJobID(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, _, err := store.CreateScan(ctx, newScan("scan_1", "fp_1")); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	// A blank job ID would defeat the purpose of the field.
	if _, err := store.RecordProviderSubmission(ctx, "scan_1", "hybrid-analysis", "", "sub", "IN_QUEUE", nil); err == nil {
		t.Error("a submission with no job ID was accepted")
	}
}

func TestIncrementAttempts(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, _, err := store.CreateScan(ctx, newScan("scan_1", "fp_1")); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	for i := 1; i <= 3; i++ {
		got, err := store.IncrementAttempts(ctx, "scan_1")
		if err != nil {
			t.Fatalf("IncrementAttempts: %v", err)
		}
		if got.Attempts != i {
			t.Errorf("attempts = %d, want %d", got.Attempts, i)
		}
	}
}

func TestListStalledScans(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, _, err := store.CreateScan(ctx, newScan("scan_1", "fp_1")); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}

	// A cut-off in the past matches nothing: the scan was just updated.
	stalled, err := store.ListStalledScans(ctx, time.Now().UTC().Add(-time.Hour), 10)
	if err != nil {
		t.Fatalf("ListStalledScans: %v", err)
	}
	if len(stalled) != 0 {
		t.Errorf("got %d stalled scans, want 0 for a cut-off in the past", len(stalled))
	}

	// A cut-off in the future matches the just-created scan, which is older
	// than any future instant.
	stalled, err = store.ListStalledScans(ctx, time.Now().UTC().Add(time.Hour), 10)
	if err != nil {
		t.Fatalf("ListStalledScans: %v", err)
	}
	if len(stalled) != 1 {
		t.Errorf("got %d stalled scans, want 1", len(stalled))
	}
}

// ------------------------------------------------------------ assessments

func newAssessment(fingerprint, scanID string, v verdicts.Verdict, expires time.Time) mongostore.Assessment {
	return mongostore.Assessment{
		URLFingerprint: fingerprint,
		ScanID:         scanID,
		Verdict:        v,
		AnalyzedAt:     time.Now().UTC(),
		ExpiresAt:      expires,
		Evidence:       []mongostore.Evidence{{Type: "provider_verdict", Summary: "test"}},
	}
}

func TestPutAndGetAssessment(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	exp := time.Now().UTC().Add(time.Hour)

	stored, err := store.PutAssessment(ctx,
		newAssessment("fp_1", "scan_1", verdicts.Suspicious, exp))
	if err != nil {
		t.Fatalf("PutAssessment: %v", err)
	}
	if stored.Verdict != verdicts.Suspicious {
		t.Errorf("verdict = %q", stored.Verdict)
	}

	got, err := store.GetAssessmentByFingerprint(ctx, "fp_1")
	if err != nil {
		t.Fatalf("GetAssessmentByFingerprint: %v", err)
	}
	if got.ScanID != "scan_1" {
		t.Errorf("scan_id = %q", got.ScanID)
	}
	if !got.IsFresh(time.Now().UTC()) {
		t.Error("a verdict expiring in an hour is not fresh")
	}
}

// PutAssessment upserts on _id, so a retried worker cannot duplicate a verdict.
func TestPutAssessmentIsIdempotent(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	exp := time.Now().UTC().Add(time.Hour)

	for i := 0; i < 3; i++ {
		if _, err := store.PutAssessment(ctx,
			newAssessment("fp_1", "scan_1", verdicts.Malicious, exp)); err != nil {
			t.Fatalf("PutAssessment %d: %v", i, err)
		}
	}

	count, err := store.Database().
		Collection(mongostore.CollectionAssessments).
		CountDocuments(ctx, bson.M{"_id": "fp_1"})
	if err != nil {
		t.Fatalf("CountDocuments: %v", err)
	}
	if count != 1 {
		t.Errorf("%d assessment documents for one fingerprint, want 1", count)
	}
}

func TestPutAssessmentValidatesInput(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	exp := time.Now().UTC().Add(time.Hour)

	if _, err := store.PutAssessment(ctx, mongostore.Assessment{ScanID: "s", Verdict: verdicts.Malicious, ExpiresAt: exp}); err == nil {
		t.Error("an assessment with no fingerprint was accepted")
	}
	if _, err := store.PutAssessment(ctx, mongostore.Assessment{URLFingerprint: "fp", Verdict: verdicts.Malicious, ExpiresAt: exp}); err == nil {
		t.Error("an assessment with no scan ID was accepted")
	}
	// An invalid verdict must not be persisted: it would be served as if it
	// meant something.
	if _, err := store.PutAssessment(ctx, newAssessment("fp", "s", "benign", exp)); err == nil {
		t.Error("an assessment with an undefined verdict was accepted")
	}
	if _, err := store.PutAssessment(ctx, mongostore.Assessment{URLFingerprint: "fp", ScanID: "s", Verdict: verdicts.Malicious}); err == nil {
		t.Error("an assessment with no expiry was accepted")
	}
}

func TestEvidenceSummaryIsBounded(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	a := newAssessment("fp_1", "scan_1", verdicts.Malicious, time.Now().UTC().Add(time.Hour))
	a.Evidence = []mongostore.Evidence{{Type: "x", Summary: strings.Repeat("A", 5000)}}

	stored, err := store.PutAssessment(ctx, a)
	if err != nil {
		t.Fatalf("PutAssessment: %v", err)
	}
	if len(stored.Evidence[0].Summary) > 500 {
		t.Errorf("evidence summary is %d chars; it reaches the browser extension", len(stored.Evidence[0].Summary))
	}
}

// A stale verdict must behave exactly like an absent one to every caller, so
// no caller can accidentally serve it.
func TestFindFreshAssessmentHidesExpiredVerdicts(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, err := store.PutAssessment(ctx,
		newAssessment("fp_1", "scan_1", verdicts.Malicious, time.Now().UTC().Add(-time.Minute))); err != nil {
		t.Fatalf("PutAssessment: %v", err)
	}

	if _, err := store.FindFreshAssessment(ctx, "fp_1", time.Now().UTC()); !errors.Is(err, mongostore.ErrAssessmentNotFound) {
		t.Errorf("an expired verdict was returned as fresh: %v", err)
	}
	// It is still retrievable when freshness is not required.
	if _, err := store.GetAssessmentByFingerprint(ctx, "fp_1"); err != nil {
		t.Errorf("GetAssessmentByFingerprint: %v", err)
	}
}

func TestExpireAndDeleteExpiredAssessments(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, err := store.PutAssessment(ctx,
		newAssessment("fp_fresh", "scan_1", verdicts.Malicious, time.Now().UTC().Add(time.Hour))); err != nil {
		t.Fatalf("PutAssessment fresh: %v", err)
	}
	if _, err := store.PutAssessment(ctx,
		newAssessment("fp_stale", "scan_2", verdicts.NoThreatDetected, time.Now().UTC().Add(-time.Hour))); err != nil {
		t.Fatalf("PutAssessment stale: %v", err)
	}

	expired, err := store.ExpiredAssessments(ctx, time.Now().UTC(), 10)
	if err != nil {
		t.Fatalf("ExpiredAssessments: %v", err)
	}
	if len(expired) != 1 || expired[0].URLFingerprint != "fp_stale" {
		t.Fatalf("expired = %+v, want only fp_stale", expired)
	}

	if err := store.ExpireAssessment(ctx, "fp_stale"); err != nil {
		t.Fatalf("ExpireAssessment: %v", err)
	}
	if _, err := store.GetAssessmentByFingerprint(ctx, "fp_stale"); !errors.Is(err, mongostore.ErrAssessmentNotFound) {
		t.Errorf("error = %v, want ErrAssessmentNotFound after explicit expiry", err)
	}

	// The fresh one must survive a sweep.
	if _, err := store.FindFreshAssessment(ctx, "fp_fresh", time.Now().UTC()); err != nil {
		t.Errorf("a fresh verdict was swept: %v", err)
	}
}

func TestGetAssessmentByScanID(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()

	if _, err := store.PutAssessment(ctx,
		newAssessment("fp_1", "scan_1", verdicts.Inconclusive, time.Now().UTC().Add(time.Hour))); err != nil {
		t.Fatalf("PutAssessment: %v", err)
	}

	got, err := store.GetAssessmentByScanID(ctx, "scan_1")
	if err != nil {
		t.Fatalf("GetAssessmentByScanID: %v", err)
	}
	if got.Verdict != verdicts.Inconclusive {
		t.Errorf("verdict = %q", got.Verdict)
	}
}

// ------------------------------------------------------- transient URLs

func TestTransientURLRoundTrip(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	aead := testAEAD(t)

	const url = "https://login.example.test/verify?token=s3cr3tvalue"

	if err := store.PutTransientURL(ctx, aead, "scan_1", url, time.Minute); err != nil {
		t.Fatalf("PutTransientURL: %v", err)
	}

	// The plaintext must not be readable in the raw document.
	var raw bson.M
	if err := store.Database().Collection(mongostore.CollectionTransientURLs).
		FindOne(ctx, bson.M{"_id": "scan_1"}).Decode(&raw); err != nil {
		t.Fatalf("read raw: %v", err)
	}
	if strings.Contains(fmt.Sprint(raw), "s3cr3tvalue") {
		t.Errorf("the stored document contains the plaintext URL: %v", raw)
	}
	for _, field := range []string{"url", "raw_url", "plaintext"} {
		if _, ok := raw[field]; ok {
			t.Errorf("the stored document has a %q field", field)
		}
	}

	got, err := store.GetTransientURL(ctx, aead, "scan_1")
	if err != nil {
		t.Fatalf("GetTransientURL: %v", err)
	}
	if got != url {
		t.Errorf("decrypted = %q, want the original", got)
	}
}

func TestTakeTransientURLDeletesOnRead(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	aead := testAEAD(t)

	if err := store.PutTransientURL(ctx, aead, "scan_1", "https://example.test/", time.Minute); err != nil {
		t.Fatalf("PutTransientURL: %v", err)
	}

	if _, err := store.TakeTransientURL(ctx, aead, "scan_1"); err != nil {
		t.Fatalf("TakeTransientURL: %v", err)
	}

	// Deletion is part of the read, so the plaintext cannot be fetched twice.
	if _, err := store.GetTransientURL(ctx, aead, "scan_1"); !errors.Is(err, mongostore.ErrTransientURLNotFound) {
		t.Errorf("error = %v, want ErrTransientURLNotFound after Take", err)
	}
}

func TestTransientURLErrors(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	aead := testAEAD(t)

	if _, err := store.GetTransientURL(ctx, aead, "missing"); !errors.Is(err, mongostore.ErrTransientURLNotFound) {
		t.Errorf("error = %v, want ErrTransientURLNotFound", err)
	}
	if err := store.PutTransientURL(ctx, aead, "scan_1", "", time.Minute); err == nil {
		t.Error("an empty URL was accepted")
	}
	if err := store.PutTransientURL(ctx, nil, "scan_1", "https://x.test/", time.Minute); !errors.Is(err, mongostore.ErrEncryptionKeyInvalid) {
		t.Error("a nil cipher was accepted")
	}
}

// A tampered record must fail loudly rather than yield a wrong URL to submit.
func TestTamperedTransientURLIsRejected(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	aead := testAEAD(t)

	if err := store.PutTransientURL(ctx, aead, "scan_1", "https://example.test/a", time.Minute); err != nil {
		t.Fatalf("PutTransientURL: %v", err)
	}

	if _, err := store.Database().Collection(mongostore.CollectionTransientURLs).
		UpdateOne(ctx, bson.M{"_id": "scan_1"}, bson.M{"$set": bson.M{"ciphertext": "dGFtcGVyZWQ="}}); err != nil {
		t.Fatalf("tamper: %v", err)
	}

	if _, err := store.GetTransientURL(ctx, aead, "scan_1"); !errors.Is(err, mongostore.ErrDecryptFailed) {
		t.Errorf("error = %v, want ErrDecryptFailed", err)
	}
}

// The AAD binding must hold across a real database write.
func TestTransientURLCannotBeSwappedBetweenScans(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	aead := testAEAD(t)

	if err := store.PutTransientURL(ctx, aead, "scan_A", "https://a.test/", time.Minute); err != nil {
		t.Fatalf("PutTransientURL: %v", err)
	}
	if err := store.PutTransientURL(ctx, aead, "scan_B", "https://b.test/", time.Minute); err != nil {
		t.Fatalf("PutTransientURL: %v", err)
	}

	// Copy A's ciphertext over B's record.
	var a bson.M
	if err := store.Database().Collection(mongostore.CollectionTransientURLs).
		FindOne(ctx, bson.M{"_id": "scan_A"}).Decode(&a); err != nil {
		t.Fatalf("read: %v", err)
	}
	if _, err := store.Database().Collection(mongostore.CollectionTransientURLs).
		UpdateOne(ctx, bson.M{"_id": "scan_B"}, bson.M{
			"$set": bson.M{"ciphertext": a["ciphertext"], "nonce": a["nonce"]},
		}); err != nil {
		t.Fatalf("swap: %v", err)
	}

	if _, err := store.GetTransientURL(ctx, aead, "scan_B"); !errors.Is(err, mongostore.ErrDecryptFailed) {
		t.Errorf("error = %v, want ErrDecryptFailed after a ciphertext swap", err)
	}
}

// One URL per scan: a second Put must not silently create a second plaintext.
func TestTransientURLIsUniquePerScan(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	aead := testAEAD(t)

	if err := store.PutTransientURL(ctx, aead, "scan_1", "https://a.test/", time.Minute); err != nil {
		t.Fatalf("first PutTransientURL: %v", err)
	}
	if err := store.PutTransientURL(ctx, aead, "scan_1", "https://b.test/", time.Minute); err == nil {
		t.Error("a second URL was stored for the same scan")
	}
}

// -------------------------------------------------- privacy across collections

// No document in any collection may contain a raw URL or a provider API key.
func TestNoDocumentCarriesRawURLOrAPIKey(t *testing.T) {
	store := testDB(t)
	ctx := t.Context()
	aead := testAEAD(t)

	const rawURL = "https://login.example.test/verify?token=s3cr3tvalue"
	const apiKey = "si71zoFAKEKEYMUSTNOTAPPEAR"

	if _, _, err := store.CreateScan(ctx, newScan("scan_1", "fp_1")); err != nil {
		t.Fatalf("CreateScan: %v", err)
	}
	if _, err := store.PutAssessment(ctx,
		newAssessment("fp_1", "scan_1", verdicts.Malicious, time.Now().UTC().Add(time.Hour))); err != nil {
		t.Fatalf("PutAssessment: %v", err)
	}
	if err := store.PutTransientURL(ctx, aead, "scan_1", rawURL, time.Minute); err != nil {
		t.Fatalf("PutTransientURL: %v", err)
	}

	for _, coll := range []string{
		mongostore.CollectionScans,
		mongostore.CollectionAssessments,
		mongostore.CollectionTransientURLs,
	} {
		cursor, err := store.Database().Collection(coll).Find(ctx, bson.M{})
		if err != nil {
			t.Fatalf("find %s: %v", coll, err)
		}
		var docs []bson.M
		if err := cursor.All(ctx, &docs); err != nil {
			t.Fatalf("decode %s: %v", coll, err)
		}
		for _, doc := range docs {
			rendered := fmt.Sprint(doc)
			if strings.Contains(rendered, apiKey) {
				t.Errorf("%s document contains the API key", coll)
			}
			if strings.Contains(rendered, rawURL) && coll != mongostore.CollectionTransientURLs {
				t.Errorf("%s document contains the plaintext URL", coll)
			}
			if strings.Contains(rendered, "s3cr3tvalue") && coll != mongostore.CollectionTransientURLs {
				t.Errorf("%s document contains the URL query token", coll)
			}
		}
	}
}
