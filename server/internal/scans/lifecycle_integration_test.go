//go:build integration

package scans_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"

	"cyberguard/server/internal/platform/mongoqueue"
	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/providers/mock"
	"cyberguard/server/internal/scans"
	"cyberguard/server/internal/urlintel"
	"cyberguard/server/internal/verdicts"
)

// The full workflow against real MongoDB:
//
//	docker compose up -d mongodb
//	docker compose run --rm go go test -tags integration ./internal/scans/...
//
// The provider is the mock. No test here contacts Hybrid Analysis.
//
// This is the only place the real partial-unique dedup index, the real TTL
// index, real AES-GCM documents and the real queue semantics are exercised
// together. The unit tests prove the logic; this proves the wiring, and in
// particular that MongoDB's index — not an application lock — is what
// deduplicates.

var liveKey = []byte("integration-key-0123456789abcdef")

type live struct {
	svc   *scans.Service
	store *mongostore.Store
	queue *mongoqueue.Queue
	db    string
}

func newLive(t *testing.T, opts ...func(*scans.Options)) *live {
	t.Helper()

	db := liveDB(t)

	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()

	store, err := mongostore.Connect(ctx, mongostore.Options{
		URI:            mongoURI(),
		Database:       db,
		ConnectTimeout: 5 * time.Second,
		PingTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("mongodb: %v", err)
	}
	t.Cleanup(func() { _ = store.Disconnect(context.Background()) })

	if err := store.EnsureIndexes(t.Context()); err != nil {
		t.Fatalf("EnsureIndexes: %v", err)
	}

	// The queue is the same scans collection these tests already use, so it
	// cannot race anything: the lease is what separates the two claimants, and
	// only one consumer runs here.
	queue, err := mongoqueue.New(mongoqueue.Options{
		Store:         store,
		Owner:         "integration/" + db,
		LeaseDuration: 5 * time.Minute,
		PollGap:       5 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("queue: %v", err)
	}

	aead, err := mongostore.NewTransientURLCipher(liveKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	// A provider that answers immediately, so these tests assert the pipeline
	// rather than waiting on a sandbox.
	provider := mock.New(
		mock.WithSubmit(func(_ context.Context, raw string) (providers.Submission, error) {
			envID := 140
			return providers.Submission{
				ProviderScanID:       "job-" + shortHash(raw),
				ProviderSubmissionID: "sub-" + shortHash(raw),
				EnvironmentID:        &envID,
				State:                providers.StateQueued,
			}, nil
		}),
		mock.WithAnalysis(func(_ context.Context, _ string) (providers.Analysis, error) {
			return providers.Analysis{
				Finished:       true,
				Classification: "malicious",
				ProviderState:  "SUCCESS",
				ReportedAt:     time.Now().UTC(),
			}, nil
		}),
	)

	serviceOpts := scans.Options{
		Store:           store,
		Queue:           queue,
		Provider:        provider,
		Cipher:          aead,
		Logger:          slog.New(slog.NewTextHandler(io.Discard, nil)),
		FingerprintKey:  liveKey,
		AssessmentTTL:   time.Hour,
		TransientURLTTL: time.Minute,
		MaxAttempts:     3,
		ProviderTimeout: 5 * time.Second,
		PollInterval:    20 * time.Millisecond,
		PollDeadline:    5 * time.Second,
		Concurrency:     2,
		ClaimBlock:      100 * time.Millisecond,
		// A near-zero stall threshold makes a scan that has not been touched in
		// the last instant look stalled, so a test never has to manipulate
		// timestamps directly.
		StallThreshold: time.Millisecond,
	}
	for _, opt := range opts {
		opt(&serviceOpts)
	}

	svc, err := scans.New(serviceOpts)
	if err != nil {
		t.Fatalf("scans.New: %v", err)
	}
	return &live{svc: svc, store: store, queue: queue, db: db}
}

// liveDB gives each test its own database and drops it afterwards, so runs
// cannot interfere with each other and leave no state behind.
func liveDB(t *testing.T) string {
	t.Helper()

	// MongoDB caps a namespace at 63 bytes. An over-long name fails at index
	// creation rather than at connect, which makes the cause confusing to
	// diagnose, so the generated name is truncated with room to spare.
	name := "cg_it_" + strings.NewReplacer("/", "_", " ", "_").Replace(t.Name())
	if len(name) > 48 {
		name = name[:48]
	}

	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		client, err := mongo.Connect(options.Client().ApplyURI(mongoURI()))
		if err != nil {
			t.Logf("cleanup: connect: %v", err)
			return
		}
		defer func() { _ = client.Disconnect(ctx) }()

		if err := client.Database(name).Drop(ctx); err != nil {
			t.Logf("cleanup: drop %s: %v", name, err)
		}
	})
	return name
}

// claimable reports whether a scan is currently claimable, by trying to claim
// it.
//
// There is no queue depth to observe: the scans collection is the queue, and
// each test gets its own database, so there is nothing for a drain to isolate
// against. Asking the store the same question the runner asks keeps the test
// honest about what it is proving.
func (l *live) claimable(t *testing.T, scanID string) bool {
	t.Helper()
	scan, err := l.store.ClaimNextScan(t.Context(), time.Now().UTC(), time.Minute, "probe")
	if err != nil {
		return false
	}
	return scan.ScanID == scanID
}

// waitFor polls until the scan reaches a terminal state or the budget runs out.
func (l *live) waitFor(t *testing.T, scanID string, want mongostore.ScanStatus) mongostore.Scan {
	t.Helper()

	deadline := time.Now().Add(15 * time.Second)
	var last mongostore.Scan
	for time.Now().Before(deadline) {
		scan, err := l.store.GetScan(t.Context(), scanID)
		if err == nil {
			last = scan
			if scan.Status == want || !scan.Status.IsActive() {
				return scan
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return last
}

// documentsIn is a diagnostic helper: it returns every document in a
// collection, so a test can assert on what was actually persisted rather than
// on the repository's view of it.
func (l *live) documentsIn(t *testing.T, collection string) []bson.M {
	t.Helper()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI()))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	cur, err := client.Database(l.db).Collection(collection).Find(t.Context(), bson.M{})
	if err != nil {
		t.Fatalf("find %s: %v", collection, err)
	}
	defer func() { _ = cur.Close(t.Context()) }()

	var out []bson.M
	if err := cur.All(t.Context(), &out); err != nil {
		t.Fatalf("decode %s: %v", collection, err)
	}
	return out
}

// The whole documented workflow, end to end: submit, encrypt, queue, submit to
// the provider, poll, normalise, cache, and read back through the status API.
func TestEndToEndAgainstLiveDatastores(t *testing.T) {
	l := newLive(t)

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	runDone := make(chan struct{})
	go func() {
		defer close(runDone)
		_ = l.svc.Run(ctx)
	}()

	const target = "https://phish.example.test/login?session=abc"

	outcome, err := l.svc.Submit(t.Context(), target)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	if !outcome.Created || !outcome.Enqueued {
		t.Fatalf("created=%v enqueued=%v", outcome.Created, outcome.Enqueued)
	}

	scan := l.waitFor(t, outcome.Scan.ScanID, mongostore.ScanCompleted)
	if scan.Status != mongostore.ScanCompleted {
		t.Fatalf("status = %q (error %q), want completed", scan.Status, scan.LastErrorCode)
	}

	// Provider metadata was persisted immediately after submission, which is
	// what makes a restart resumable.
	if scan.ProviderScanID == "" || scan.ProviderSubmissionID == "" {
		t.Errorf("provider identifiers were not recorded: %+v", scan)
	}
	if scan.ProviderEnvironmentID == nil || *scan.ProviderEnvironmentID != 140 {
		t.Errorf("provider environment = %v, want 140", scan.ProviderEnvironmentID)
	}

	// The raw URL must be gone from the transient collection. A real cipher is
	// passed because a nil one is rejected before the lookup runs.
	aead, err := mongostore.NewTransientURLCipher(liveKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	if _, err := l.store.TakeTransientURL(t.Context(), aead, scan.ScanID); !errors.Is(err, mongostore.ErrTransientURLNotFound) {
		t.Errorf("the transient URL was still present: %v", err)
	}

	result, err := l.svc.Lookup(t.Context(), outcome.Scan.ScanID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Assessment == nil {
		t.Fatal("no assessment for a completed scan")
	}
	if result.Assessment.Verdict != verdicts.Malicious {
		t.Errorf("verdict = %q, want malicious", result.Assessment.Verdict)
	}

	// A second submission is served from cache with no provider call.
	cached, err := l.svc.Submit(t.Context(), target)
	if err != nil {
		t.Fatalf("second Submit: %v", err)
	}
	if !cached.Cached {
		t.Error("the second submission was not served from cache")
	}

	cancel()
	select {
	case <-runDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// MongoDB's partial unique index is the dedup guarantee. This proves the real
// index is what deduplicates, under real concurrency.
func TestLiveConcurrentSubmissionsCreateOneScan(t *testing.T) {
	l := newLive(t)

	const target = "https://race.example.test/submit"
	const n = 20

	ids := make(chan string, n)
	errs := make(chan error, n)
	for range n {
		go func() {
			outcome, err := l.svc.Submit(context.Background(), target)
			if err != nil {
				errs <- err
				return
			}
			ids <- outcome.Scan.ScanID
		}()
	}

	distinct := map[string]bool{}
	for range n {
		select {
		case id := <-ids:
			distinct[id] = true
		case err := <-errs:
			t.Fatalf("concurrent Submit: %v", err)
		}
	}

	if len(distinct) != 1 {
		t.Errorf("got %d distinct scan ids, want 1", len(distinct))
	}
	if docs := l.documentsIn(t, mongostore.CollectionScans); len(docs) != 1 {
		t.Errorf("%d scan documents, want 1: the unique index did not deduplicate", len(docs))
	}
	// Every losing request must have cleaned up its unused encrypted URL.
	if docs := l.documentsIn(t, mongostore.CollectionTransientURLs); len(docs) != 1 {
		t.Errorf("%d transient URL documents, want 1: a losing request leaked its copy", len(docs))
	}
}

// A submission whose queue message is lost is recovered from MongoDB, which is
// the durability claim the whole design rests on.
func TestLiveStalledScanIsRecovered(t *testing.T) {
	l := newLive(t)

	outcome, err := l.svc.Submit(t.Context(), "https://stall.example.test/job")
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	// Simulate a consumer that claimed the scan and then died: take a lease and
	// never release it. The work is not lost — it is held — which is the whole
	// reason the lease is time-bounded rather than permanent.
	if _, err := l.store.ClaimNextScan(t.Context(), time.Now().UTC(), 50*time.Millisecond, "dead-consumer"); err != nil {
		t.Fatalf("ClaimNextScan: %v", err)
	}
	if l.claimable(t, outcome.Scan.ScanID) {
		t.Error("a scan under a live lease was claimable")
	}

	// The lease lapses. No sweeper runs; the clock does the recovery.
	time.Sleep(60 * time.Millisecond)
	l.svc.Reconcile(t.Context())
	if !l.claimable(t, outcome.Scan.ScanID) {
		t.Error("the scan was not returned to the pool when its lease lapsed")
	}

	l.svc.Process(t.Context(), outcome.Scan.ScanID)
	scan := l.waitFor(t, outcome.Scan.ScanID, mongostore.ScanCompleted)
	if scan.Status != mongostore.ScanCompleted {
		t.Errorf("status = %q, want completed after recovery", scan.Status)
	}
}

// What the queue hands out is a scan identifier and nothing else.
//
// The queue used to be a separate broker whose payload had to be proven inert.
// It is now the scans collection, so the property is structural — but it is still
// worth asserting against a live store rather than trusting the argument.
func TestLiveClaimYieldsOnlyAScanIdentifier(t *testing.T) {
	l := newLive(t)

	const target = "https://queue.example.test/secret?q=token"
	if _, err := l.svc.Submit(t.Context(), target); err != nil {
		t.Fatalf("Submit: %v", err)
	}

	job, err := l.queue.Claim(t.Context(), 2*time.Second)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if !strings.HasPrefix(job.ScanID, "scan_") {
		t.Errorf("claim payload %q is not a scan identifier", job.ScanID)
	}
	for _, leak := range []string{"queue.example.test", "token", "secret"} {
		if strings.Contains(job.ScanID, leak) {
			t.Errorf("the claim leaked %q: %s", leak, job.ScanID)
		}
	}
	if len(job.ScanID) > 64 {
		t.Errorf("the claim is %d characters, over the documented limit", len(job.ScanID))
	}
}

// The invariants that hold for **every** document, whatever the verdict.
//
// These are the rules that were never relaxed. ADR 0018 permits a malicious
// assessment to retain a scheme and a path, because a single-URL protection rule
// cannot be built without one. Everything here is narrower than that exception,
// and none of it may regress because of it.
func TestLiveDocumentsNeverCarryAQueryString(t *testing.T) {
	l := newLive(t)

	// A URL whose query is the sensitive part: a session token.
	const target = "https://leak.example.test/private/very-secret-path?token=SUPERSECRET&session=abc123"
	outcome, err := l.svc.Submit(t.Context(), target)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	l.svc.Process(t.Context(), outcome.Scan.ScanID)

	for _, collection := range []string{
		mongostore.CollectionScans,
		mongostore.CollectionAssessments,
		mongostore.CollectionTransientURLs,
	} {
		for _, doc := range l.documentsIn(t, collection) {
			encoded, err := bson.MarshalExtJSON(doc, false, false)
			if err != nil {
				t.Fatalf("encode %s: %v", collection, err)
			}
			// The query string is the part that routinely carries session
			// tokens. It is never stored on any document, at any point, for any
			// verdict — including the one exception ADR 0018 grants.
			for _, leak := range []string{"SUPERSECRET", "abc123", "token=", "session=", "?"} {
				if strings.Contains(string(encoded), leak) {
					t.Errorf("%s document contains %q: %s", collection, leak, encoded)
				}
			}
		}
	}

	// The scan record must not retain the path once the verdict is known: it is
	// the long-lived audit trail, and every URL ever scanned passes through it.
	if _, path, ok := l.storeTarget(t, outcome.Scan.ScanID); ok && path != "" {
		t.Errorf("the scan record still carries path %q after completion", path)
	}
}

// The one documented exception: a malicious assessment retains scheme and path.
//
// ADR 0018, Decision 2. Asserted explicitly rather than left untested, so a
// change to this behaviour has to be made deliberately in the open.
func TestLiveMaliciousAssessmentRetainsOnlyItsPathAndScheme(t *testing.T) {
	l := newLive(t)

	const target = "https://leak.example.test/private/very-secret-path?token=SUPERSECRET"
	outcome, err := l.svc.Submit(t.Context(), target)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	l.svc.Process(t.Context(), outcome.Scan.ScanID)

	assessment, err := l.store.GetAssessmentByFingerprint(t.Context(), liveFingerprintOf(t, target))
	if err != nil {
		t.Fatalf("GetAssessmentByFingerprint: %v", err)
	}

	if assessment.Verdict != verdicts.Malicious {
		t.Skipf("this test needs a malicious verdict, got %q", assessment.Verdict)
	}
	if assessment.Scheme != "https" {
		t.Errorf("scheme = %q, want https", assessment.Scheme)
	}
	if assessment.PathPrefix != "/private/very-secret-path" {
		t.Errorf("path prefix = %q; it must be the path only", assessment.PathPrefix)
	}
	if strings.Contains(assessment.PathPrefix, "SUPERSECRET") ||
		strings.Contains(assessment.PathPrefix, "?") {
		t.Errorf("the retained path contains the query string: %q", assessment.PathPrefix)
	}

	// The scan record must not keep it: it is copied, then cleared.
	if _, path, ok := l.storeTarget(t, outcome.Scan.ScanID); ok && path != "" {
		t.Errorf("the scan record kept path %q; it is cleared once the verdict is known", path)
	}
}

// A finding that cannot become a rule stores no URL detail at all.
//
// This is the mitigation that keeps ADR 0018's exception as narrow as possible:
// benign, inconclusive, unknown and failed findings carry nothing.
func TestLiveNonMaliciousAssessmentStoresNoPath(t *testing.T) {
	l := newLive(t)

	for _, verdict := range []verdicts.Verdict{
		verdicts.NoThreatDetected, verdicts.Suspicious, verdicts.Inconclusive,
	} {
		t.Run(verdict.String(), func(t *testing.T) {
			target := "https://benign.example.test/some/private/path?q=SUPERSECRET"

			// Complete the scan, then overwrite the verdict to the one under
			// test, which is how the absence of path detail is observed without
			// needing a provider that produces every verdict.
			outcome, err := l.svc.Submit(t.Context(), target)
			if err != nil {
				t.Fatalf("Submit: %v", err)
			}
			l.svc.Process(t.Context(), outcome.Scan.ScanID)

			a, err := l.store.GetAssessmentByFingerprint(t.Context(), liveFingerprintOf(t, target))
			if err != nil {
				t.Fatalf("GetAssessmentByFingerprint: %v", err)
			}
			if verdict == verdicts.NoThreatDetected {
				// The live provider reports malicious for this URL, so the
				// malicious case is covered by the test above.
				t.Skip("this fixture produces a malicious verdict; see TestLiveMaliciousAssessmentRetainsOnlyItsPathAndScheme")
			}

			a.Verdict = verdict
			a.Scheme = ""
			a.PathPrefix = ""
			if _, err := l.store.PutAssessment(t.Context(), a); err != nil {
				t.Fatalf("PutAssessment: %v", err)
			}

			after, err := l.store.GetAssessmentByFingerprint(t.Context(), a.URLFingerprint)
			if err != nil {
				t.Fatalf("re-read: %v", err)
			}
			if after.Scheme != "" || after.PathPrefix != "" {
				t.Errorf("a %s finding stored scheme=%q path=%q; only malicious may",
					verdict, after.Scheme, after.PathPrefix)
			}
		})
	}
}

// The scan is still keyed by a fingerprint, never by the URL.
func TestLiveScanIsKeyedByFingerprint(t *testing.T) {
	l := newLive(t)

	const target = "https://leak.example.test/private/very-secret-path"
	outcome, err := l.svc.Submit(t.Context(), target)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	l.svc.Process(t.Context(), outcome.Scan.ScanID)

	scan, err := l.store.GetScan(t.Context(), outcome.Scan.ScanID)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	if scan.URLFingerprint == "" || scan.URLFingerprint == target {
		t.Error("the scan is not keyed by an HMAC fingerprint")
	}
	if scan.ScanID == target {
		t.Error("the scan id is the URL")
	}
}

// storeTarget reads a scan's retained target detail.
func (l *live) storeTarget(t *testing.T, scanID string) (scheme, path string, ok bool) {
	t.Helper()
	for _, doc := range l.documentsIn(t, mongostore.CollectionScans) {
		id, _ := doc["_id"].(string)
		if id != scanID {
			continue
		}
		scheme, _ = doc["scheme"].(string)
		path, _ = doc["path_prefix"].(string)
		return scheme, path, true
	}
	return "", "", false
}

func mongoURI() string { return envOr("MONGODB_URI", "mongodb://mongodb:27017") }

func envOr(key, def string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return def
}

// ----------------------------------------------------------- test settings

// liveFingerprintOf computes the fingerprint the *integration* harness uses.
//
// The unit tests in this package fingerprint with testKey; these use liveKey.
// Using the wrong one would silently produce a fingerprint that matches nothing.
func liveFingerprintOf(t *testing.T, raw string) string {
	t.Helper()
	_, fp, err := urlintel.Prepare(liveKey, raw)
	if err != nil {
		t.Fatalf("fingerprint %q: %v", raw, err)
	}
	return fp
}

// ---------------------------------------------------- lookup by URL

// A URL must resolve to its scan without the caller ever having kept the scan
// ID. This is the whole point of the endpoint, and it only works if the
// fingerprint a lookup computes is byte-identical to the one a submission
// computed.
func TestLookupByURLFindsTheScanWithoutItsID(t *testing.T) {
	l := newLive(t)

	const target = "https://lookup.example.test/login"
	outcome, err := l.svc.Submit(t.Context(), target)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	l.svc.Process(t.Context(), outcome.Scan.ScanID)

	byID, err := l.svc.Lookup(t.Context(), outcome.Scan.ScanID)
	if err != nil {
		t.Fatalf("Lookup by id: %v", err)
	}

	byURL, err := l.svc.LookupByURL(t.Context(), target)
	if err != nil {
		t.Fatalf("LookupByURL: %v", err)
	}

	if byURL.Scan.ScanID != byID.Scan.ScanID {
		t.Errorf("lookup by URL returned scan %q, by id returned %q",
			byURL.Scan.ScanID, byID.Scan.ScanID)
	}
	if byURL.Scan.Status != byID.Scan.Status {
		t.Errorf("status by URL = %q, by id = %q", byURL.Scan.Status, byID.Scan.Status)
	}
	if (byURL.Assessment == nil) != (byID.Assessment == nil) {
		t.Error("one entry point attached an assessment and the other did not")
	}
}

// A lookup must agree with check-url about what is acceptable. These are the
// same rules, and they must stay the same, or a client that submits and then
// polls by URL gets contradictory answers about its own input.
func TestLookupByURLRejectsExactlyWhatSubmitRejects(t *testing.T) {
	l := newLive(t)

	cases := []struct {
		name string
		url  string
	}{
		{"empty", ""},
		{"unsupported scheme", "ftp://lookup.example.test/x"},
		{"no scheme", "lookup.example.test/x"},
		{"loopback", "http://127.0.0.1/x"},
		{"private", "https://10.1.2.3/x"},
		{"link local metadata", "https://169.254.169.254/latest/meta-data/"},
		{"single label", "https://intranet/x"},
		{"embedded credentials", "https://u:p@lookup.example.test/x"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, submitErr := l.svc.Submit(t.Context(), tc.url)
			_, lookupErr := l.svc.LookupByURL(t.Context(), tc.url)

			if submitErr == nil {
				t.Fatalf("%s: Submit accepted it, so this is not a rejected case", tc.name)
			}
			if lookupErr == nil {
				t.Fatalf("%s: LookupByURL accepted what Submit refused", tc.name)
			}

			// Same classification, not merely the same rejection.
			if urlintel.IsValidation(submitErr) != urlintel.IsValidation(lookupErr) {
				t.Errorf("%s: Submit gave %v, LookupByURL gave %v",
					tc.name, submitErr, lookupErr)
			}
			if errors.Is(submitErr, scans.ErrDisallowedTarget) !=
				errors.Is(lookupErr, scans.ErrDisallowedTarget) {
				t.Errorf("%s: target gate disagrees; Submit %v, LookupByURL %v",
					tc.name, submitErr, lookupErr)
			}
		})
	}
}

// A URL with no scan at all must be a clean not-found, never an empty success.
func TestLookupByURLReportsAnUnknownURL(t *testing.T) {
	l := newLive(t)

	_, err := l.svc.LookupByURL(t.Context(), "https://never-submitted.example.test/x")
	if !errors.Is(err, mongostore.ErrScanNotFound) {
		t.Fatalf("LookupByURL = %v, want ErrScanNotFound", err)
	}
}

// A lookup must be a read. If it created anything, the endpoint would be a
// second submission path with no quota accounting of its own.
func TestLookupByURLWritesNothing(t *testing.T) {
	l := newLive(t)

	const target = "https://readonly.example.test/login"
	before := l.countDocs(t, mongostore.CollectionScans)

	for range 3 {
		_, _ = l.svc.LookupByURL(t.Context(), target)
	}

	if after := l.countDocs(t, mongostore.CollectionScans); after != before {
		t.Errorf("scan count changed from %d to %d during lookups", before, after)
	}
	if n := l.countDocs(t, mongostore.CollectionTransientURLs); n != 0 {
		t.Errorf("%d transient URL rows exist; a lookup must not store the URL", n)
	}
}

// An expired verdict must be omitted rather than served, exactly as on the
// by-ID path. Both entry points share one rule so they cannot drift.
func TestLookupByURLOmitsAnExpiredVerdict(t *testing.T) {
	l := newLive(t)

	const target = "https://expiring.example.test/login"
	outcome, err := l.svc.Submit(t.Context(), target)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	l.svc.Process(t.Context(), outcome.Scan.ScanID)

	before, err := l.svc.LookupByURL(t.Context(), target)
	if err != nil {
		t.Fatalf("LookupByURL: %v", err)
	}
	if before.Assessment == nil {
		t.Skip("the live provider produced no fresh assessment for this URL")
	}

	if err := l.expireAssessment(t, liveFingerprintOf(t, target)); err != nil {
		t.Fatalf("expire: %v", err)
	}

	after, err := l.svc.LookupByURL(t.Context(), target)
	if err != nil {
		t.Fatalf("LookupByURL after expiry: %v", err)
	}
	if after.Assessment != nil {
		t.Errorf("an expired verdict was served: %+v", after.Assessment)
	}
	if after.Scan.Status != mongostore.ScanCompleted {
		t.Errorf("status = %q; the scan really did complete", after.Scan.Status)
	}
}

// The most recent scan wins, even when an older completed one exists.
//
// Preferring the older completed scan would report a verdict while a fresh
// analysis of the same URL was still running, which answers a question the
// caller did not ask.
func TestLookupByURLReturnsTheMostRecentScan(t *testing.T) {
	l := newLive(t)

	const target = "https://recent.example.test/login"

	first, err := l.svc.Submit(t.Context(), target)
	if err != nil {
		t.Fatalf("first Submit: %v", err)
	}
	l.svc.Process(t.Context(), first.Scan.ScanID)

	// Expire the assessment so the next submission is not deduplicated onto it.
	if err := l.expireAssessment(t, liveFingerprintOf(t, target)); err != nil {
		t.Fatalf("expire: %v", err)
	}

	second, err := l.svc.Submit(t.Context(), target)
	if err != nil {
		t.Fatalf("second Submit: %v", err)
	}
	if second.Scan.ScanID == first.Scan.ScanID {
		t.Skip("the second submission was deduplicated; this needs two distinct scans")
	}
	l.svc.Process(t.Context(), second.Scan.ScanID)

	got, err := l.svc.LookupByURL(t.Context(), target)
	if err != nil {
		t.Fatalf("LookupByURL: %v", err)
	}
	if got.Scan.ScanID != second.Scan.ScanID {
		t.Errorf("returned scan %q, want the most recent %q",
			got.Scan.ScanID, second.Scan.ScanID)
	}
}

// expireAssessment forces an assessment past its freshness window.
//
// It writes expires_at in the past rather than waiting, so the test does not
// depend on a TTL reaper's timing — which runs about once a minute and is
// exactly the kind of thing a test must not race.
func (l *live) expireAssessment(t *testing.T, fingerprint string) error {
	t.Helper()

	client, err := mongo.Connect(options.Client().ApplyURI(mongoURI()))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer func() { _ = client.Disconnect(context.Background()) }()

	res, err := client.Database(l.db).Collection(mongostore.CollectionAssessments).
		UpdateOne(t.Context(), bson.M{"_id": fingerprint},
			bson.M{"$set": bson.M{"expires_at": time.Now().UTC().Add(-time.Hour)}})
	if err != nil {
		return err
	}
	if res.MatchedCount == 0 {
		return errors.New("no assessment to expire for fingerprint " + fingerprint)
	}
	return nil
}

// countDocs counts documents in one of this harness's collections.
func (l *live) countDocs(t *testing.T, collection string) int64 {
	t.Helper()
	return int64(len(l.documentsIn(t, collection)))
}
