package services

// Tests for the cache-first check-url flow.
//
// The fake store implements the same semantics as Mongo's guarantees, in
// memory: a unique urlHash, guarded writes that never move a record
// backward, and atomic rescan resets. The fake analyzer never contacts a
// real provider.

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"cyberguard/internal/hybridanalysis"
	"cyberguard/internal/models"
)

// ---------------------------------------------------------------------------
// fakes
// ---------------------------------------------------------------------------

// fakeAnalyzer is a threaded-safe canned provider. Retrieval replies repeat
// the last canned result once the sequence is exhausted (so "always
// unfinished" is one unfinished result).
type fakeAnalyzer struct {
	mu sync.Mutex

	// submission side
	submits      int
	submitted    []string
	submitResult hybridanalysis.Result
	submitErr    error

	// retrieval side
	gets     int
	gotIDs   []string
	getSeq   []hybridanalysis.Result
	getIdx   int
	getError func(call int) error
}

func (f *fakeAnalyzer) QuickScanURL(ctx context.Context, rawURL string) (hybridanalysis.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.submits++
	f.submitted = append(f.submitted, rawURL)
	return f.submitResult, f.submitErr
}

func (f *fakeAnalyzer) GetQuickScanResult(ctx context.Context, quickScanID string) (hybridanalysis.Result, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gets++
	f.gotIDs = append(f.gotIDs, quickScanID)
	if f.getError != nil {
		if err := f.getError(f.gets); err != nil {
			return hybridanalysis.Result{}, err
		}
	}
	if len(f.getSeq) == 0 {
		// A canned-empty reply: not finished, no scanner data.
		return hybridanalysis.Result{ID: quickScanID}, nil
	}
	res := f.getSeq[f.getIdx]
	if f.getIdx < len(f.getSeq)-1 {
		f.getIdx++
	}
	return res, nil
}

// memStore is an in-memory SubmissionStore with Mongo's behaviour made
// explicit, so the service's guarded-flow assumptions are tested against the
// same semantics the real database provides:
//
//   - the uniq_url_hash index rejects a second insert of the same hash;
//   - SavePendingProgress and SaveFinalResult refuse a completed record;
//   - ResetForRescan only resets stale completed records.
type memStore struct {
	mu      sync.Mutex
	records []*models.Submission
	idSeq   int

	// published-version state, exactly as Mongo would keep it
	ruleState *models.RulesetState

	// injected failures
	findErr    error
	insertErr  error
	updateErr  error
	stateErr   error
	entriesErr error
	publishErr error

	// counters and traces
	inserts        int
	adopts         []string
	pendingSaves   int
	finalSaves     int
	resets         int
	inserted       []models.Submission
	duplicateSeen  bool
	publishCount   int
	publishDigests []string

	// hook, when set, runs inside InsertSubmission before its normal flow;
	// it may inject a peer write (then return a duplicate error) to emulate
	// a request racing this one across processes.
	onInsert func(sub *models.Submission) error

	// peer race simulation: when set, SaveFinalResult behaves as if a peer
	// completed the record microseconds earlier and returns matched=false.
	finalSaveBlocked bool
	peerReadyVerdict string
}

func (m *memStore) seed(sub models.Submission) *models.Submission {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.idSeq++
	sub.ID = testObjectID(m.idSeq)
	clone := sub
	m.records = append(m.records, &clone)
	return &clone
}

// appendLocked appends a record without taking the lock; callers inside
// store operations (the onInsert hook) already run under m.mu.
func (m *memStore) appendLocked(sub models.Submission) {
	clone := sub
	m.records = append(m.records, &clone)
}

func (m *memStore) find(predicate func(*models.Submission) bool) (*models.Submission, error) {
	if m.findErr != nil {
		return nil, m.findErr
	}
	for _, rec := range m.records {
		if predicate(rec) {
			return rec, nil
		}
	}
	return nil, nil
}

func (m *memStore) FindByURLHash(ctx context.Context, urlHash string) (*models.Submission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.find(func(r *models.Submission) bool { return r.URLHash == urlHash })
}

func (m *memStore) FindByRawURL(ctx context.Context, url string) (*models.Submission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.find(func(r *models.Submission) bool { return r.URL == url && r.URLHash == "" })
}

func (m *memStore) AdoptURLHash(ctx context.Context, id bson.ObjectID, urlHash string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return false, m.updateErr
	}
	for _, rec := range m.records {
		if rec.ID == id && rec.URLHash == "" {
			mrec := rec // copy of the pointer-to-value is fine; field write is guarded
			mrec.URLHash = urlHash
			m.adopts = append(m.adopts, urlHash)
			return true, nil
		}
	}
	return false, nil
}

func (m *memStore) InsertSubmission(ctx context.Context, sub *models.Submission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.inserts++
	if m.insertErr != nil {
		return m.insertErr
	}
	if m.onInsert != nil {
		if err := m.onInsert(sub); err != nil {
			return err
		}
	}
	for _, rec := range m.records {
		if sub.URLHash != "" && rec.URLHash == sub.URLHash {
			m.duplicateSeen = true
			return mongo.CommandError{Code: 11000, Message: "E11000 duplicate key error collection"}
		}
	}
	m.idSeq++
	sub.ID = testObjectID(m.idSeq)
	clone := *sub
	m.records = append(m.records, &clone)
	m.inserted = append(m.inserted, *sub)
	return nil
}

func (m *memStore) SavePendingProgress(ctx context.Context, id bson.ObjectID, stage *models.Submission) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return false, m.updateErr
	}
	m.pendingSaves++
	rec := m.byID(id)
	if rec == nil {
		return false, nil // the record vanished; matched=0, like Mongo
	}
	if rec.IsCompleted() {
		return false, nil // guard: completed assessments are immutable here
	}
	rec.Status = models.StatusPending
	rec.Finished = false
	rec.UpdatedAt = stage.UpdatedAt
	if stage.SHA256 != "" {
		rec.SHA256 = stage.SHA256
	}
	if stage.Scanners != nil {
		rec.Scanners = stage.Scanners
	}
	if len(stage.ScannersV2) > 0 {
		rec.ScannersV2 = stage.ScannersV2
	}
	if stage.Reports != nil {
		rec.Reports = stage.Reports
	}
	return true, nil
}

func (m *memStore) SaveFinalResult(ctx context.Context, id bson.ObjectID, final *models.Submission) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return false, m.updateErr
	}
	m.finalSaves++
	rec := m.byID(id)
	if rec == nil {
		return false, nil // the record vanished; matched=0, like Mongo
	}
	if m.finalSaveBlocked {
		// A peer completed the record moments earlier: emulate exactly
		// that and refuse the write.
		rec.Status = models.StatusCompleted
		rec.Finished = true
		v := m.peerReadyVerdict
		rec.Verdict = &v
		return false, nil
	}
	if rec.IsCompleted() {
		return false, nil
	}
	rec.SHA256 = final.SHA256
	rec.ScanType = final.ScanType
	rec.Status = models.StatusCompleted
	rec.Finished = true
	rec.Scanners = final.Scanners
	rec.ScannersV2 = final.ScannersV2
	rec.Reports = final.Reports
	rec.Verdict = final.Verdict
	rec.UpdatedAt = final.UpdatedAt
	return true, nil
}

func (m *memStore) ResetForRescan(ctx context.Context, id bson.ObjectID, expiredBefore time.Time, stage *models.Submission) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.updateErr != nil {
		return false, m.updateErr
	}
	m.resets++
	rec := m.byID(id)
	if rec == nil {
		return false, nil // the record vanished; matched=0, like Mongo
	}
	if rec.IsCompleted() && !expiredBefore.After(rec.UpdatedAt) {
		// completed and NOT expired: the guard must refuse.
		return false, nil
	}
	rec.ProviderID = stage.ProviderID
	rec.SHA256 = ""
	rec.ScanType = stage.ScanType
	rec.Status = models.StatusPending
	rec.Finished = false
	rec.Verdict = nil
	rec.Scanners = nil
	rec.ScannersV2 = nil
	rec.Reports = nil
	rec.UpdatedAt = stage.UpdatedAt
	return true, nil
}

func (m *memStore) RulesetState(ctx context.Context) (*models.RulesetState, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.stateErr != nil {
		return nil, false, m.stateErr
	}
	if m.ruleState == nil {
		return nil, false, nil
	}
	clone := *m.ruleState
	return &clone, true, nil
}

// RulesetEntries mirrors the real store's query: the eligibility filter
// (completed, published verdict, updatedAt inside the freshness window) and
// the deterministic row order (URL ascending, updatedAt descending). It does
// NOT deduplicate: multiple pre-hashing legacy rows may share a URL, and the
// service's deterministic fold must deal with that.
func (m *memStore) RulesetEntries(ctx context.Context, cutoff time.Time) ([]models.RulesetEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entriesErr != nil {
		return nil, m.entriesErr
	}

	// Sort the underlying records exactly as Mongo would (url asc, then
	// updatedAt desc — freshest first), and project afterwards. This keeps
	// the deduplication the service applies deterministic.
	type row struct {
		updated time.Time
		sub     *models.Submission
	}

	eligible := make([]row, 0, len(m.records))
	for _, rec := range m.records {
		if !rec.IsCompleted() || rec.Verdict == nil || !publishedVerdict(*rec.Verdict) {
			continue
		}
		if rec.UpdatedAt.Before(cutoff) {
			continue
		}
		eligible = append(eligible, row{updated: rec.UpdatedAt, sub: rec})
	}
	sort.Slice(eligible, func(i, j int) bool {
		if eligible[i].sub.URL != eligible[j].sub.URL {
			return eligible[i].sub.URL < eligible[j].sub.URL
		}
		return eligible[i].updated.After(eligible[j].updated)
	})

	entries := make([]models.RulesetEntry, 0, len(eligible))
	for _, r := range eligible {
		entries = append(entries, models.RulesetEntry{URL: r.sub.URL, Verdict: *r.sub.Verdict})
	}
	return entries, nil
}

// PublishRulesetState reproduces the store's content-addressed bump: a publish
// of unchanged content is a no-op; a changed digest increments the version
// exactly once; the first-ever publish creates version 1.
func (m *memStore) PublishRulesetState(ctx context.Context, digest string, now time.Time) (*models.RulesetState, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.publishCount++
	m.publishDigests = append(m.publishDigests, digest)
	if m.publishErr != nil {
		return nil, false, m.publishErr
	}
	if m.ruleState == nil {
		m.ruleState = &models.RulesetState{ID: models.RulesetStateID, Version: 1, Digest: digest, UpdatedAt: now}
		return m.cloneState(1), true, nil
	}
	if m.ruleState.Digest == digest {
		clone := *m.ruleState
		return &clone, false, nil
	}
	m.ruleState.Version++
	m.ruleState.Digest = digest
	m.ruleState.UpdatedAt = now
	return m.cloneState(m.ruleState.Version), true, nil
}

func (m *memStore) cloneState(v int64) *models.RulesetState {
	clone := *m.ruleState
	clone.Version = v
	return &clone
}

func (m *memStore) byID(id bson.ObjectID) *models.Submission {
	for _, rec := range m.records {
		if rec.ID == id {
			return rec
		}
	}
	return nil
}

func (m *memStore) last() *models.Submission {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.records) == 0 {
		return nil
	}
	return m.records[len(m.records)-1]
}

func testObjectID(n int) bson.ObjectID {
	id, err := bson.ObjectIDFromHex(fmt.Sprintf("%024x", n))
	if err != nil {
		panic(err)
	}
	return id
}

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

// testOptions keeps every wait inside milliseconds while remaining nonzero,
// so deadline paths are exercised quickly.
func testOptions(wait, poll time.Duration) ServiceOptions {
	return ServiceOptions{AssessmentTTL: 24 * time.Hour, WaitBudget: wait, PollInterval: poll}
}

func cleanFinishedResult(id string) hybridanalysis.Result {
	return hybridanalysis.Result{
		ID: id, SHA256: "cleandigest", ScanType: "all", Finished: true,
		ScannersV2: scannersV2(map[string]string{
			"bfore_ai": "clean", "clean_dns": "clean", "scam_adviser": "clean",
		}),
	}
}

func maliciousFinishedResult(id string) hybridanalysis.Result {
	return hybridanalysis.Result{
		ID: id, SHA256: "evildigest", ScanType: "all", Finished: true,
		ScannersV2: scannersV2(map[string]string{"metadefender": "malicious"}),
	}
}

func unfinishedResult(id string) hybridanalysis.Result {
	return hybridanalysis.Result{
		ID: id, ScanType: "all", Finished: false,
		ScannersV2: scannersV2(map[string]string{"a": "malicious"}),
	}
}

func seedPending(store *memStore, url, providerID string, updated time.Time) *models.Submission {
	return store.seed(models.Submission{
		URL: url, Provider: models.ProviderName, ProviderID: providerID,
		ScanType: "all", Status: models.StatusPending,
		CreatedAt: updated, UpdatedAt: updated,
	})
}

func seedCompleted(store *memStore, url, verdict string, updated time.Time) *models.Submission {
	v := verdict
	return store.seed(models.Submission{
		URL: url, Provider: models.ProviderName, ProviderID: "qs-old-" + verdict,
		ScanType: "all", Status: models.StatusCompleted, Finished: true,
		Verdict: &v, CreatedAt: updated, UpdatedAt: updated,
	})
}

// ---------------------------------------------------------------------------
// canonicalization
// ---------------------------------------------------------------------------

func TestValidateURL(t *testing.T) {
	cases := []struct {
		name    string
		in      string
		wantErr bool
		want    string // expected canonical value, when valid
	}{
		{"path and query preserved", "https://example.com/path?q=1", false, "https://example.com/path?q=1"},
		{"ip host", "http://192.0.2.10/admin", false, "http://192.0.2.10/admin"},
		{"non-default port preserved", "http://example.com:8080/", false, "http://example.com:8080/"},
		{"uppercase non-default port preserved", "HTTPS://EXAMPLE.COM:8443/X", false, "https://example.com:8443/X"},
		{"default port and fragment removed", "HTTPS://Example.COM:443/a?b=1#frag", false, "https://example.com/a?b=1"},
		{"scheme and host lowercased", "HTTPS://EXAMPLE.com/a", false, "https://example.com/a"},
		{"query order untouched", "https://example.com/p?b=2&a=1", false, "https://example.com/p?b=2&a=1"},
		{"whitespace trimmed", "  https://example.com  ", false, "https://example.com"},
		{"empty", "", true, ""},
		{"only spaces", "   ", true, ""},
		{"no scheme", "example.com", true, ""},
		{"ftp scheme", "ftp://example.com/x", true, ""},
		{"javascript scheme", "javascript:alert(1)", true, ""},
		{"data scheme", "data:text/html,<b>x</b>", true, ""},
		{"missing host", "https://", true, ""},
		{"control characters", "https://exa\tmple.com", true, ""},
		{"too long", "https://example.com/" + strings.Repeat("a", MaxURLLength), true, ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateURL(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("ValidateURL(%q): want error, got %q", tc.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("ValidateURL(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("ValidateURL(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestCanonicalURLHashIsStable(t *testing.T) {
	// One canonicalization, one cache key: whitespace, case and default
	// port differences must not split the cache.
	a, err := ValidateURL("HTTPS://Example.com:443/home")
	if err != nil {
		t.Fatal(err)
	}
	b, err := ValidateURL("  https://example.com/home  ")
	if err != nil {
		t.Fatal(err)
	}
	if canonicalURLHash(a) != canonicalURLHash(b) {
		t.Errorf("hashes differ: %s vs %s", canonicalURLHash(a), canonicalURLHash(b))
	}
}

// ---------------------------------------------------------------------------
// submission flow
// ---------------------------------------------------------------------------

func TestCheckURLSubmitStoresThenRetrievesFinal(t *testing.T) {
	// A cold URL: submit once (pending), then the documented retrieval
	// endpoint returns the finished result, which is normalized and stored.
	analyzer := &fakeAnalyzer{
		submitResult: hybridanalysis.Result{ID: "qs-42", SHA256: "deadbeef", ScanType: "all"},
		getSeq:       []hybridanalysis.Result{cleanFinishedResult("qs-42")},
	}
	store := &memStore{}
	svc := New(store, analyzer, testOptions(5*time.Second, 20*time.Millisecond))

	sub, serr := svc.CheckURL(context.Background(), "https://example.com")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}

	if analyzer.submits != 1 {
		t.Errorf("submission calls = %d, want exactly one", analyzer.submits)
	}
	if analyzer.submitted[0] != "https://example.com" {
		t.Errorf("submitted URL = %q", analyzer.submitted[0])
	}
	if len(analyzer.gotIDs) != 1 || analyzer.gotIDs[0] != "qs-42" {
		t.Errorf("retrieval used ids %v", analyzer.gotIDs)
	}
	if store.inserts != 1 {
		t.Errorf("store inserts = %d", store.inserts)
	}

	if !sub.IsCompleted() {
		t.Errorf("status = %q, want completed", sub.Status)
	}
	if sub.Verdict == nil || *sub.Verdict != models.VerdictNoThreat {
		t.Errorf("Verdict = %v, want no_threat_detected", sub.Verdict)
	}
	if sub.Finished != true {
		t.Errorf("Finished = %v", sub.Finished)
	}
	if sub.ProviderID != "qs-42" {
		t.Errorf("ProviderID = %q", sub.ProviderID)
	}
	stored := store.last()
	if stored == nil || stored.ID != sub.ID || stored.Status != models.StatusCompleted {
		t.Errorf("final result was not persisted: %+v", stored)
	}
	if stored.Verdict == nil || *stored.Verdict != models.VerdictNoThreat {
		t.Errorf("stored Verdict = %v", stored.Verdict)
	}
}

func TestCheckURLSubmitAlreadyFinishedStoresCompleted(t *testing.T) {
	// The submission itself may be finished: a verdict is derived at once,
	// stored, and no retrieval happens.
	analyzer := &fakeAnalyzer{submitResult: cleanFinishedResult("qs-9")}
	store := &memStore{}
	svc := New(store, analyzer, testOptions(time.Second, 10*time.Millisecond))

	sub, serr := svc.CheckURL(context.Background(), "https://example.com")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}
	if analyzer.gets != 0 {
		t.Errorf("retrieval happened although the submission was finished (%d times)", analyzer.gets)
	}
	if analyzer.submits != 1 {
		t.Errorf("submission calls = %d", analyzer.submits)
	}
	if !sub.IsCompleted() || sub.Verdict == nil || *sub.Verdict != models.VerdictNoThreat {
		t.Errorf("submission result = %+v", sub)
	}
	stored := store.last()
	if stored == nil || stored.Status != models.StatusCompleted {
		t.Fatalf("composite record missing: %+v", stored)
	}
	if stored.Verdict == nil || *stored.Verdict != models.VerdictNoThreat {
		t.Fatalf("stored verdict missing: %v", stored.Verdict)
	}
	if stored.ID != sub.ID {
		t.Errorf("returned id %s, stored id %s", sub.ID.Hex(), stored.ID.Hex())
	}
}

// test 1: a completed URL in MongoDB is returned without a provider call.
func TestCheckURLCacheHitSkipsProvider(t *testing.T) {
	store := &memStore{}
	seedCompleted(store, "https://example.com", "suspicious", time.Now().UTC())
	analyzer := &fakeAnalyzer{}
	svc := New(store, analyzer, testOptions(time.Second, 10*time.Millisecond))

	sub, serr := svc.CheckURL(context.Background(), "https://example.com")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}
	if analyzer.submits != 0 || analyzer.gets != 0 {
		t.Errorf("provider was contacted for a cached result: submits=%d gets=%d", analyzer.submits, analyzer.gets)
	}
	if store.inserts != 0 {
		t.Errorf("a second record was written (%d)", store.inserts)
	}
	if sub.Status != models.StatusCompleted || sub.Verdict == nil || *sub.Verdict != "suspicious" {
		t.Errorf("served record = %+v", sub)
	}
}

// test 2 (+3): a missing URL is submitted exactly once; an in-flight
// equivalent request never duplicates the submission.
func TestCheckURLConcurrentRequestDeduplicatesSubmission(t *testing.T) {
	analyzer := &fakeAnalyzer{
		submitResult: hybridanalysis.Result{ID: "qs-par", ScanType: "all", Finished: false},
		getSeq:       []hybridanalysis.Result{cleanFinishedResult("qs-par")},
	}
	store := &memStore{}
	svc := New(store, analyzer, testOptions(5*time.Second, 20*time.Millisecond))

	const n = 12
	var wg sync.WaitGroup
	results := make([]*models.Submission, n)
	errs := make([]*Error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			results[i], errs[i] = svc.CheckURL(context.Background(), "https://example.com/cached-url")
		}(i)
	}
	close(start)
	wg.Wait()

	if analyzer.submits != 1 {
		t.Errorf("submission calls = %d, want exactly one", analyzer.submits)
	}
	if store.inserts != 1 {
		t.Errorf("records inserted = %d, want one", store.inserts)
	}
	for i, sub := range results {
		if errs[i] != nil {
			t.Errorf("request %d failed: %+v", i, errs[i])
			continue
		}
		if sub.IsCompleted() && sub.Verdict != nil && *sub.Verdict != models.VerdictNoThreat {
			t.Errorf("request %d verdict = %v", i, sub.Verdict)
		}
	}
}

// test 5: a pending record reuses its existing provider ID and is not
// submitted again.
func TestCheckURLPendingReusesProviderID(t *testing.T) {
	store := &memStore{}
	seedPending(store, "https://example.com/pending", "qs-old", time.Now().UTC())
	analyzer := &fakeAnalyzer{getSeq: []hybridanalysis.Result{cleanFinishedResult("qs-old")}}
	svc := New(store, analyzer, testOptions(5*time.Second, 20*time.Millisecond))

	sub, serr := svc.CheckURL(context.Background(), "https://example.com/pending")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}
	if analyzer.submits != 0 {
		t.Errorf("a pending record was submitted again (%d times)", analyzer.submits)
	}
	if len(analyzer.gotIDs) != 1 || analyzer.gotIDs[0] != "qs-old" {
		t.Errorf("retrieval ids = %v, want the stored provider id", analyzer.gotIDs)
	}
	if !sub.IsCompleted() {
		t.Errorf("status = %q", sub.Status)
	}
	stored := store.last()
	if stored.Status != models.StatusCompleted || stored.ProviderID != "qs-old" {
		t.Errorf("stored record = %+v", stored)
	}
}

// test 6 (+8): when the deadline runs out the scan stays pending, verdict
// null — even when the unfinished response carries malicious-looking data.
func TestCheckURLPendingDeadlineReturnsPending(t *testing.T) {
	store := &memStore{}
	analyzer := &fakeAnalyzer{
		submitResult: unfinishedResult("qs-slow"),
		getSeq:       []hybridanalysis.Result{unfinishedResult("qs-slow")},
	}
	svc := New(store, analyzer, testOptions(40*time.Millisecond, 10*time.Millisecond))

	sub, serr := svc.CheckURL(context.Background(), "https://example.com/slow")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}
	if sub.IsCompleted() {
		t.Errorf("status = %q, want pending", sub.Status)
	}
	if sub.Finished {
		t.Errorf("Finished must transmit the provider's own false")
	}
	if sub.Verdict != nil {
		t.Errorf("Verdict = %v, want null for an unfinished scan", sub.Verdict)
	}
	if analyzer.submits != 1 {
		t.Errorf("submissions = %d, want exactly one while waiting", analyzer.submits)
	}
	if store.finalSaves != 0 {
		t.Errorf("a pending progress was saved as final %d times", store.finalSaves)
	}
	stored := store.last()
	if stored.Status != models.StatusPending || stored.Verdict != nil {
		t.Errorf("stored record = %+v", stored)
	}
	if stored.ScannersV2 == nil || stored.ScannersV2["a"] == nil {
		t.Errorf("the unfinished provider data was not persisted: %v", stored.ScannersV2)
	}
}

// test 12: completed assessments cannot be overwritten by pending or other
// results: a lost final save serves the peer's completed record untouched.
func TestCheckURLCompletedRecordWinsFinalWrite(t *testing.T) {
	store := &memStore{finalSaveBlocked: true, peerReadyVerdict: "malicious"}
	analyzer := &fakeAnalyzer{
		submitResult: hybridanalysis.Result{ID: "qs-race", ScanType: "all"},
		getSeq:       []hybridanalysis.Result{cleanFinishedResult("qs-race")},
	}
	svc := New(store, analyzer, testOptions(5*time.Second, 20*time.Millisecond))

	sub, serr := svc.CheckURL(context.Background(), "https://example.com/race")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}
	if sub.Verdict == nil || *sub.Verdict != "malicious" {
		t.Errorf("the completed record must win, got verdict %v", sub.Verdict)
	}
	if store.last().Verdict == nil || *store.last().Verdict != "malicious" {
		t.Errorf("the stored verdict was overwritten: %v", store.last().Verdict)
	}
}

// test 14: completed assessments cannot be overwritten by pending or other
// results, and a request that loses an insert race (the winner is another
// process) adopts the winner's record instead of submitting again.
func TestCheckURLDuplicateInsertAdoptsWinnersRecord(t *testing.T) {
	store := &memStore{}
	now := time.Now().UTC()
	dupHash := canonicalURLHash("https://example.com/dupe")

	// Emulate the race: while this request is submitting, a concurrent
	// process inserted the same canonical URL. Its record shows up; this
	// process's insert is rejected with the duplicate-key error.
	store.onInsert = func(sub *models.Submission) error {
		if sub.URLHash == dupHash {
			winner := models.Submission{
				URL: sub.URL, URLHash: sub.URLHash, Provider: models.ProviderName,
				ProviderID: "qs-peer", ScanType: "all", Status: models.StatusPending,
				CreatedAt: now, UpdatedAt: now,
			}
			store.appendLocked(winner) // already under the store's lock inside Insert
			return mongo.CommandError{Code: 11000, Message: "E11000 duplicate key error collection"}
		}
		return nil
	}

	analyzer := &fakeAnalyzer{getSeq: []hybridanalysis.Result{cleanFinishedResult("qs-peer")}}
	svc := New(store, analyzer, testOptions(5*time.Second, 20*time.Millisecond))

	sub, serr := svc.CheckURL(context.Background(), "https://example.com/dupe")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}
	if analyzer.submits != 1 {
		t.Errorf("submission calls = %d, want exactly one", analyzer.submits)
	}
	if store.duplicateSeen {
		t.Error("the duplicate path ran twice")
	}
	if len(store.records) != 1 {
		t.Errorf("records = %d, want exactly the winner's", len(store.records))
	}
	if len(analyzer.gotIDs) != 1 || analyzer.gotIDs[0] != "qs-peer" {
		t.Errorf("retrieval ids = %v, want the winner's provider id", analyzer.gotIDs)
	}
	if !sub.IsCompleted() || sub.Verdict == nil {
		t.Errorf("result = %+v", sub)
	}
}

// ---------------------------------------------------------------------------
// legacy records without a hash are adopted
// ---------------------------------------------------------------------------

func TestCheckURLLegacyRecordIsAdopted(t *testing.T) {
	store := &memStore{}
	// A pre-URL-hashing record: no urlHash, legacy "submitted" status.
	store.seed(models.Submission{
		URL: "https://example.com/legacy", Provider: models.ProviderName,
		ProviderID: "qs-legacy", ScanType: "all",
		Status:    models.LegacyStatusSubmitted,
		CreatedAt: time.Now().UTC(), UpdatedAt: time.Now().UTC(),
	})
	analyzer := &fakeAnalyzer{getSeq: []hybridanalysis.Result{cleanFinishedResult("qs-legacy")}}
	svc := New(store, analyzer, testOptions(5*time.Second, 20*time.Millisecond))

	sub, serr := svc.CheckURL(context.Background(), "https://example.com/legacy")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}
	if len(store.adopts) != 1 {
		t.Errorf("adoptions = %d", len(store.adopts))
	}
	if analyzer.submits != 0 {
		t.Errorf("the legacy pending record was resubmitted (%d times)", analyzer.submits)
	}
	if len(analyzer.gotIDs) != 1 || analyzer.gotIDs[0] != "qs-legacy" {
		t.Errorf("retrieval ids = %v", analyzer.gotIDs)
	}
	if !sub.IsCompleted() {
		t.Errorf("status = %q", sub.Status)
	}
	// The adopted record must now carry the canonical hash.
	stored := store.last()
	if stored.URLHash != canonicalURLHash("https://example.com/legacy") {
		t.Errorf("urlHash not adopted: %q", stored.URLHash)
	}
}

// ---------------------------------------------------------------------------
// expiry
// ---------------------------------------------------------------------------

func TestCheckURLExpiredCompletedResubmits(t *testing.T) {
	store := &memStore{}
	ttl := time.Hour
	seedCompleted(store, "https://example.com/stale", "no_threat_detected", time.Now().UTC().Add(-2*ttl))

	analyzer := &fakeAnalyzer{
		submitResult: hybridanalysis.Result{ID: "qs-new", ScanType: "all", Finished: false},
		getSeq:       []hybridanalysis.Result{cleanFinishedResult("qs-new")},
	}
	svc := New(store, analyzer, ServiceOptions{AssessmentTTL: ttl, WaitBudget: 5 * time.Second, PollInterval: 20 * time.Millisecond})

	sub, serr := svc.CheckURL(context.Background(), "https://example.com/stale")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}
	if analyzer.submits != 1 {
		t.Errorf("an expired assessment was not re-submitted (submits=%d)", analyzer.submits)
	}
	if store.resets != 1 {
		t.Errorf("resets = %d, want the stale record reset in place", store.resets)
	}
	if len(store.records) != 1 {
		t.Errorf("records = %d; a rescan must not create a second record", len(store.records))
	}
	if !sub.IsCompleted() || sub.Verdict == nil {
		t.Errorf("result = %+v", sub)
	}
	if sub.ProviderID != "qs-new" {
		t.Errorf("ProviderID = %q", sub.ProviderID)
	}
}

// ---------------------------------------------------------------------------
// errors
// ---------------------------------------------------------------------------

func TestCheckURLRejectsBeforeAnySideEffect(t *testing.T) {
	cases := []struct {
		name  string
		input string
	}{
		{"empty url", ""},
		{"unsupported scheme", "ftp://example.com"},
		{"no host", "https://"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analyzer := &fakeAnalyzer{}
			store := &memStore{}
			svc := New(store, analyzer, testOptions(time.Second, 10*time.Millisecond))

			_, serr := svc.CheckURL(context.Background(), tc.input)
			if serr == nil {
				t.Fatal("want a validation error")
			}
			if serr.Code != CodeValidationError || serr.Status != 422 {
				t.Errorf("got %s/%d", serr.Code, serr.Status)
			}
			if analyzer.submits != 0 || analyzer.gets != 0 {
				t.Errorf("the provider was called for an invalid URL (submit=%d, get=%d)", analyzer.submits, analyzer.gets)
			}
			if len(store.inserted) != 0 {
				t.Errorf("an invalid submission was stored (%d times)", len(store.inserted))
			}
		})
	}
}

func TestCheckURLNothingStoredOnProviderError(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		wantCode   string
		wantStatus int
	}{
		{"invalid api key", fmt.Errorf("hybridanalysis: submit: status 401: %w", hybridanalysis.ErrAuth), CodeProviderAuth, 502},
		{"rate limited", &hybridanalysis.RateLimitError{RetryAfter: time.Minute, Err: hybridanalysis.ErrRateLimited}, CodeProviderRateLimit, 429},
		{"timeout", fmt.Errorf("hybridanalysis: submit: %w", hybridanalysis.ErrTimeout), CodeProviderTimeout, 504},
		{"provider rejected", fmt.Errorf("hybridanalysis: submit: status 400: %w", hybridanalysis.ErrValidation), CodeProviderRejected, 502},
		{"bad response", fmt.Errorf("hybridanalysis: decode: %w", hybridanalysis.ErrBadResponse), CodeProviderBadResp, 502},
		{"unavailable", fmt.Errorf("hybridanalysis: transport: %w", hybridanalysis.ErrUnavailable), CodeProviderUnavail, 502},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analyzer := &fakeAnalyzer{submitErr: tc.err}
			store := &memStore{}
			svc := New(store, analyzer, testOptions(time.Second, 10*time.Millisecond))

			_, serr := svc.CheckURL(context.Background(), "https://example.com")
			if serr == nil {
				t.Fatal("want a provider error")
			}
			if serr.Code != tc.wantCode || serr.Status != tc.wantStatus {
				t.Errorf("got %s/%d, want %s/%d", serr.Code, serr.Status, tc.wantCode, tc.wantStatus)
			}
			if len(store.inserted) != 0 {
				t.Errorf("errors must not be stored as results, stored = %d", len(store.inserted))
			}
			if errors.Unwrap(serr) == nil {
				t.Error("the cause must be preserved for logs")
			}
		})
	}
}

// test 10: retrieval errors are not safe results and rate limits surface.
func TestCheckURLRetrievalErrorsNeverBecomeVerdicts(t *testing.T) {
	cases := []struct {
		name       string
		getError   func(int) error
		wantCode   string
		wantStatus int
	}{
		{
			"rate limited retrieval aborts at once",
			func(int) error {
				return &hybridanalysis.RateLimitError{RetryAfter: 30 * time.Second, Err: hybridanalysis.ErrRateLimited}
			},
			CodeProviderRateLimit, 429,
		},
		{
			"auth failure aborts",
			func(int) error { return fmt.Errorf("hybridanalysis: retrieve: status 401: %w", hybridanalysis.ErrAuth) },
			CodeProviderAuth, 502,
		},
		{
			"provider lost the scan",
			func(int) error {
				return fmt.Errorf("hybridanalysis: retrieve: status 404: %w", hybridanalysis.ErrValidation)
			},
			CodeProviderRejected, 502,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			store := &memStore{}
			seedPending(store, "https://example.com/err", "qs-err", time.Now().UTC())
			analyzer := &fakeAnalyzer{getError: tc.getError}
			svc := New(store, analyzer, testOptions(5*time.Second, 10*time.Millisecond))

			_, serr := svc.CheckURL(context.Background(), "https://example.com/err")
			if serr == nil {
				t.Fatal("want a provider error")
			}
			if serr.Code != tc.wantCode || serr.Status != tc.wantStatus {
				t.Errorf("got %s/%d, want %s/%d", serr.Code, serr.Status, tc.wantCode, tc.wantStatus)
			}
			if store.finalSaves != 0 {
				t.Errorf("an error was saved as a final result %d times", store.finalSaves)
			}
			stored := store.last()
			if stored.Status != models.StatusPending && stored.Status != models.LegacyStatusSubmitted {
				t.Errorf("the record was mutated: %+v", stored)
			}
			if stored.Verdict != nil {
				t.Errorf("an error must never become a verdict, got %v", stored.Verdict)
			}
		})
	}

	t.Run("transient retrieval failures tolerate the budget then surface", func(t *testing.T) {
		store := &memStore{}
		seedPending(store, "https://example.com/transient", "qs-t", time.Now().UTC())
		analyzer := &fakeAnalyzer{
			getError: func(int) error { return fmt.Errorf("hybridanalysis: retrieve: %w", hybridanalysis.ErrUnavailable) },
		}
		svc := New(store, analyzer, testOptions(40*time.Millisecond, 10*time.Millisecond))

		_, serr := svc.CheckURL(context.Background(), "https://example.com/transient")
		if serr == nil {
			t.Fatal("want a provider error after the budget ran out")
		}
		if serr.Code != CodeProviderUnavail || serr.Status != 502 {
			t.Errorf("got %s/%d", serr.Code, serr.Status)
		}
		stored := store.last()
		if stored.Status != models.StatusPending || stored.Verdict != nil {
			t.Errorf("the record was mutated: %+v", stored)
		}
	})
}

func TestCheckURLStoreFailure(t *testing.T) {
	analyzer := &fakeAnalyzer{submitResult: cleanFinishedResult("qs-x")}
	store := &memStore{insertErr: errors.New("write: connection reset")}
	svc := New(store, analyzer, testOptions(time.Second, 10*time.Millisecond))

	_, serr := svc.CheckURL(context.Background(), "https://example.com")
	if serr == nil || serr.Code != CodeStoreUnavailable || serr.Status != 503 {
		t.Fatalf("got %+v, want store_unavailable/503", serr)
	}
	if errors.Unwrap(serr) == nil || !strings.Contains(errors.Unwrap(serr).Error(), "connection reset") {
		t.Error("the store cause must be preserved for logs")
	}
}

func TestCheckURLWithoutAnalyzerIsHonest(t *testing.T) {
	store := &memStore{}
	svc := New(store, nil, testOptions(time.Second, 10*time.Millisecond))

	_, serr := svc.CheckURL(context.Background(), "https://example.com")
	if serr == nil || serr.Code != CodeProviderMissingKey || serr.Status != 503 {
		t.Fatalf("got %+v, want provider_not_configured/503", serr)
	}
	if store.inserts != 0 {
		t.Error("nothing must be stored when the provider is not configured")
	}
}

func TestCheckURLNilScannersV2StaysAbsent(t *testing.T) {
	// The provider can omit scanners_v2; nothing is invented for it, and a
	// finished response with no usable evidence maps to "unknown", not to a
	// clean verdict.
	analyzer := &fakeAnalyzer{submitResult: hybridanalysis.Result{
		ID: "qs-x", Finished: true, ScanType: "all",
	}}
	store := &memStore{}
	svc := New(store, analyzer, testOptions(time.Second, 10*time.Millisecond))

	sub, serr := svc.CheckURL(context.Background(), "https://example.com")
	if serr != nil {
		t.Fatalf("CheckURL: %+v", serr)
	}
	if sub.ScannersV2 != nil {
		t.Errorf("ScannersV2 = %v, want nil", sub.ScannersV2)
	}
	if sub.Verdict == nil || *sub.Verdict != models.VerdictUnknown {
		t.Errorf("Verdict = %v, want unknown", sub.Verdict)
	}
}

// ---------------------------------------------------------------------------
// version-aware ruleset listing
// ---------------------------------------------------------------------------

// threatRecord seeds one completed record the publishing policy accepts.
func threatRecord(url, verdict string, at time.Time) models.Submission {
	v := verdict
	return models.Submission{
		URL: url, URLHash: canonicalURLHash(url),
		Provider: models.ProviderName, ProviderID: "qs-" + url,
		ScanType: "all",
		Status:   models.StatusCompleted, Finished: true,
		Verdict:   &v,
		CreatedAt: at, UpdatedAt: at,
	}
}

func TestRulesetListing(t *testing.T) {
	fixed := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)

	newSvc := func(store *memStore) *Service {
		// A nil analyzer: listing never contacts the provider.
		return New(store, nil, testOptions(time.Second, 10*time.Millisecond))
	}

	t.Run("missing version delivers the complete published ruleset", func(t *testing.T) {
		store := &memStore{}
		// Eligible: one malicious, one suspicious. Ineligible: pending,
		// clean, inconclusive, unknown and a verdict-less legacy record.
		store.seed(threatRecord("https://threat-a.example", models.VerdictMalicious, fixed))
		store.seed(threatRecord("https://threat-b.example", models.VerdictSuspicious, fixed))
		store.seed(threatRecord("https://clean.example", models.VerdictNoThreat, fixed))
		store.seed(threatRecord("https://grey.example", models.VerdictInconclusive, fixed))
		store.seed(threatRecord("https://muted.example", models.VerdictUnknown, fixed))
		store.seed(models.Submission{
			URL: "https://pending.example", URLHash: canonicalURLHash("https://pending.example"),
			Provider: models.ProviderName, ScanType: "all",
			Status: models.StatusPending, CreatedAt: fixed, UpdatedAt: fixed,
		})

		view, serr := newSvc(store).List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if !view.Updated {
			t.Error("a first-time client must receive the full ruleset (updated=true)")
		}
		if view.Version != 1 {
			t.Errorf("Version = %d, want 1 (the first published snapshot)", view.Version)
		}
		var got []string
		for _, e := range view.Entries {
			got = append(got, e.URL)
		}
		want := []string{"https://threat-a.example", "https://threat-b.example"}
		if strings.Join(got, ",") != strings.Join(want, ",") {
			t.Errorf("entries = %v, want exactly %v in URL order (publishable threats only)", got, want)
		}
	})

	t.Run("matching version answers from the version document alone", func(t *testing.T) {
		store := &memStore{}
		store.seed(threatRecord("https://threat.example", models.VerdictMalicious, fixed))
		svc := newSvc(store)
		if _, serr := svc.List(context.Background(), nil); serr != nil {
			t.Fatalf("initial List: %+v", serr)
		}

		// A broken entries read would fail a full delivery — proving the
		// matched path never touches the URL collection.
		store.mu.Lock()
		store.entriesErr = errors.New("find: unready")
		store.mu.Unlock()
		v := int64(1)
		view, serr := svc.List(context.Background(), &v)
		if serr != nil {
			t.Fatalf("matched List: %+v", serr)
		}
		if view.Updated || view.Version != 1 || len(view.Entries) != 0 {
			t.Errorf("view = %+v, want an empty up-to-date answer at version 1", view)
		}
	})

	t.Run("different version delivers the full current snapshot", func(t *testing.T) {
		store := &memStore{}
		store.seed(threatRecord("https://threat.example", models.VerdictMalicious, fixed))
		svc := newSvc(store)
		if _, serr := svc.List(context.Background(), nil); serr != nil {
			t.Fatalf("initial List: %+v", serr)
		}

		for _, stale := range []int64{0, 2, 5, 12345} {
			view, serr := svc.List(context.Background(), &[]int64{stale}[0])
			if serr != nil {
				t.Fatalf("List(%d): %+v", stale, serr)
			}
			if !view.Updated || view.Version != 1 {
				t.Errorf("List(%d) = (%v, version %d)", stale, view.Updated, view.Version)
			}
			if len(view.Entries) != 1 || view.Entries[0].URL != "https://threat.example" {
				t.Errorf("List(%d) entries = %+v", stale, view.Entries)
			}
		}
	})

	t.Run("empty ruleset is a valid versioned response", func(t *testing.T) {
		store := &memStore{}
		svc := newSvc(store)

		// First-time client: version 1, empty data — a real (empty)
		// published snapshot, not an error.
		view, serr := svc.List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if view.Version != 1 || !view.Updated || len(view.Entries) != 0 {
			t.Errorf("empty ruleset = (%d, %v, %d entries)", view.Version, view.Updated, len(view.Entries))
		}

		// A matching client on the empty snapshot: still tiny and exact.
		one := int64(1)
		view, serr = svc.List(context.Background(), &one)
		if serr != nil {
			t.Fatalf("List(1): %+v", serr)
		}
		if view.Updated || view.Version != 1 || len(view.Entries) != 0 {
			t.Errorf("matched empty snapshot = (%v, %d, %d entries)", view.Updated, view.Version, len(view.Entries))
		}
	})

	t.Run("listing never changes the version", func(t *testing.T) {
		store := &memStore{}
		store.seed(threatRecord("https://threat.example", models.VerdictMalicious, fixed))
		svc := newSvc(store)
		if _, serr := svc.List(context.Background(), nil); serr != nil {
			t.Fatalf("initial List: %+v", serr)
		}
		store.mu.Lock()
		publishes := store.publishCount
		store.mu.Unlock()

		for range 5 {
			if _, serr := svc.List(context.Background(), nil); serr != nil {
				t.Fatalf("List: %+v", serr)
			}
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		if store.publishCount != publishes || store.ruleState.Version != 1 {
			t.Errorf("get-all republished (%d vs %d) or bumped the version to %d",
				store.publishCount, publishes, store.ruleState.Version)
		}
	})

	t.Run("a missed publish reconciles without serving a mixed snapshot", func(t *testing.T) {
		store := &memStore{}
		store.seed(threatRecord("https://a.example", models.VerdictMalicious, fixed))
		svc := newSvc(store)
		if _, serr := svc.List(context.Background(), nil); serr != nil {
			t.Fatalf("initial List: %+v", serr)
		}

		// Content changed behind the publisher's back (the stored digest
		// is now stale). The stored state still claims the old digest,
		// simulating a crash between a final save and its publish.
		store.seed(threatRecord("https://b.example", models.VerdictSuspicious, fixed))

		view, serr := svc.List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if view.Version != 2 {
			t.Errorf("Version = %d, want 2 (the missing publish is reconciled)", view.Version)
		}
		if !view.Updated || len(view.Entries) != 2 {
			t.Errorf("view = %+v, want the complete reconciled snapshot", view)
		}
	})

	t.Run("store failures are reported, never served as data", func(t *testing.T) {
		store := &memStore{entriesErr: errors.New("find: closed")}
		_, serr := newSvc(store).List(context.Background(), nil)
		if serr == nil || serr.Code != CodeStoreUnavailable || serr.Status != 503 {
			t.Fatalf("got %+v, want store_unavailable/503", serr)
		}
	})
}

// rulesetPublishing covers the content-addressed version changes the check-url
// flow drives.
func TestRulesetPublishing(t *testing.T) {
	fixed := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)

	t.Run("a finalized verdict publishes through the check-url flow", func(t *testing.T) {
		store := &memStore{}
		analyzer := &fakeAnalyzer{
			submitResult: hybridanalysis.Result{ID: "qs-77", ScanType: "all"},
			getSeq: []hybridanalysis.Result{
				unfinishedResult("qs-77"),
				// The retrieval reply repeats this finished result, so
				// the second URL below finishes on its first GET.
				maliciousFinishedResult("qs-77"),
			},
		}
		svc := New(store, analyzer, testOptions(5*time.Second, 20*time.Millisecond))

		// First URL: submit, polls once (unfinished), then finishes.
		// Pending progress saves happen on the way without publishing.
		sub, serr := svc.CheckURL(context.Background(), "https://attack.example")
		if serr != nil {
			t.Fatalf("CheckURL: %+v", serr)
		}
		if !sub.IsCompleted() || sub.Verdict == nil || *sub.Verdict != models.VerdictMalicious {
			t.Fatalf("finalized sub = %+v", sub)
		}

		view, serr := svc.List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if view.Version != 1 || len(view.Entries) != 1 ||
			view.Entries[0].URL != "https://attack.example" ||
			view.Entries[0].Verdict != models.VerdictMalicious {
			t.Fatalf("published = (%d, %+v), want the finalized malicious rule at version 1", view.Version, view.Entries)
		}
		store.mu.Lock()
		publishes := store.publishCount
		store.mu.Unlock()

		// Second URL finalizes inside this request: the published
		// content grows, and the version bumps — from the write that
		// changed it, without any get-all reconcile.
		if _, serr := svc.CheckURL(context.Background(), "https://attack-two.example"); serr != nil {
			t.Fatalf("second CheckURL: %+v", serr)
		}
		view, serr = svc.List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if view.Version != 2 || len(view.Entries) != 2 {
			t.Fatalf("after second finalization = (%d, %d entries), want version 2 with 2 rules", view.Version, len(view.Entries))
		}
		store.mu.Lock()
		defer store.mu.Unlock()
		if store.publishCount != publishes+1 {
			t.Errorf("publishes = %d, want exactly the one content change (+%d); get-all published the rest",
				store.publishCount, publishes)
		}
	})

	t.Run("changed published content bumps the version exactly once", func(t *testing.T) {
		store := &memStore{}
		store.seed(threatRecord("https://a.example", models.VerdictMalicious, fixed))
		svc := New(store, nil, testOptions(time.Second, 10*time.Millisecond))

		_, serr := svc.List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("initial List: %+v", serr)
		}

		// A second URL becomes eligible: the published content changes.
		store.seed(threatRecord("https://b.example", models.VerdictSuspicious, fixed))

		view, serr := svc.List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if view.Version != 2 {
			t.Errorf("Version = %d, want 2", view.Version)
		}
		if len(view.Entries) != 2 {
			t.Errorf("entries = %d, want 2", len(view.Entries))
		}
	})

	t.Run("unchanged published content never bumps the version", func(t *testing.T) {
		store := &memStore{}
		store.seed(threatRecord("https://a.example", models.VerdictMalicious, fixed))
		svc := New(store, nil, testOptions(time.Second, 10*time.Millisecond))
		view, serr := svc.List(context.Background(), nil)
		if serr != nil || view.Version != 1 {
			t.Fatalf("initial List = (%d, %+v), want version 1", view.Version, serr)
		}

		// Touch the record (a rescan refreshing updatedAt) without
		// changing the published content: same URL, same verdict. The
		// version must not move.
		touch := func() {
			store.mu.Lock()
			rec := store.byID(store.records[0].ID)
			rec.UpdatedAt = fixed.Add(time.Minute)
			store.mu.Unlock()
		}
		touch()
		view, serr = svc.List(context.Background(), nil)
		if serr != nil || view.Version != 1 || !view.Updated {
			t.Fatalf("identical content = (%d, %+v), want version 1 unchanged", view.Version, serr)
		}
	})

	t.Run("expired records leave the published snapshot", func(t *testing.T) {
		store := &memStore{}
		staleSeed := threatRecord("https://stale.example", models.VerdictMalicious, fixed)
		staleSeed.UpdatedAt = fixed.Add(-48 * time.Hour)
		store.seed(staleSeed)

		// Default TTL 24h: the expired record is not publishable, so the
		// very first snapshot is empty.
		view, serr := New(store, nil, testOptions(time.Second, 10*time.Millisecond)).
			List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if len(view.Entries) != 0 || view.Version != 1 {
			t.Errorf("expired-first ruleset = (%d entries, version %d)", len(view.Entries), view.Version)
		}
	})

	t.Run("duplicate legacy rows for one URL yield one rule", func(t *testing.T) {
		store := &memStore{}
		// Two pre-hashing legacy records for the same canonical URL: no
		// unique index conflicts (hash absent), and both hold a verdict.
		a := threatRecord("https://dup.example", models.VerdictSuspicious, fixed)
		a.URLHash = ""
		b := threatRecord("https://dup.example", models.VerdictMalicious, fixed.Add(-time.Hour))
		b.URLHash = ""
		store.seed(b)
		store.seed(a) // fresher row: its verdict must win deterministically

		view, serr := New(store, nil, testOptions(time.Second, 10*time.Millisecond)).
			List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if len(view.Entries) != 1 {
			t.Fatalf("entries = %+v, want one rule for the duplicated URL", view.Entries)
		}
		if view.Entries[0].Verdict != models.VerdictSuspicious {
			t.Errorf("verdict = %q, want the freshest record's %q", view.Entries[0].Verdict, models.VerdictSuspicious)
		}
	})

	t.Run("the version document survives a restart", func(t *testing.T) {
		store := &memStore{}
		store.seed(threatRecord("https://threat.example", models.VerdictMalicious, fixed))
		svc := New(store, nil, testOptions(time.Second, 10*time.Millisecond))
		if _, serr := svc.List(context.Background(), nil); serr != nil {
			t.Fatalf("initial List: %+v", serr)
		}

		// A "restarted" process is a fresh service over the same store:
		// the version must still be there, unchanged.
		view, serr := New(store, nil, testOptions(time.Second, 10*time.Millisecond)).
			List(context.Background(), nil)
		if serr != nil {
			t.Fatalf("List after restart: %+v", serr)
		}
		if view.Version != 1 {
			t.Errorf("Version = %d after restart, want the persisted 1", view.Version)
		}
	})
}

// TestDNRRuleMapping pins the mapping from stored data onto the
// extension-facing declarativeNetRequest shape. The ruleset body (get-all)
// and the check-url data.rule are pure functions of the stored URL and
// verdict, so pinning the helpers pins every presentation surface.
func TestDNRRuleMapping(t *testing.T) {
	t.Run("the urlFilter mirrors the stored URL", func(t *testing.T) {
		cases := []struct {
			raw  string
			want string
		}{
			// Root URLs: host plus one separator — no end anchor.
			{"https://example.com/", "||example.com^"},
			{"https://example.com", "||example.com^"},
			// Host + path, closed with the end anchor.
			{"https://Example.COM/download", "||example.com^/download|"},
			{"https://sub.host/path?q=v", "||sub.host^/path?q=v|"},
			{"https://host:8443/p", "||host:8443^/p|"},
			// A root URL with a query still pins its query.
			{"https://host/?q=v", "||host^?q=v|"},
			// Anything unparseable or host-less yields no filter at all.
			{"not-a-url-at-all", ""},
			{"%zz", ""},
			{"mailto:someone@example.com", ""},
		}
		for _, tc := range cases {
			if got := dnrURLFilter(tc.raw); got != tc.want {
				t.Errorf("dnrURLFilter(%q) = %q, want %q", tc.raw, got, tc.want)
			}
		}
	})

	t.Run("the snapshot maps onto installable rules with ids 1..N", func(t *testing.T) {
		view := &RulesetView{
			Version: 3, Updated: true,
			Entries: []models.RulesetEntry{
				{URL: "https://a.example/", Verdict: models.VerdictMalicious},
				{URL: "https://b.example/x", Verdict: models.VerdictSuspicious},
			},
		}
		rules := RulesetRules(view)
		if len(rules) != 2 {
			t.Fatalf("rules = %d entries, want 2", len(rules))
		}
		for i, rule := range rules {
			if rule.ID == nil || *rule.ID != int64(i+1) {
				t.Errorf("rules[%d].id = %v, want %d", i, rule.ID, i+1)
			}
			if rule.Priority != 1 || rule.Action.Type != "block" {
				t.Errorf("rules[%d] = %+v, want a priority-1 block rule", i, rule)
			}
			if !rule.Condition.IsURLFilterCaseSensitive ||
				len(rule.Condition.ResourceTypes) != len(models.DNRResourceTypes) {
				t.Errorf("rules[%d].condition = %+v, want the constant match condition", i, rule.Condition)
			}
		}
		if got, want := rules[0].Condition.URLFilter, "||a.example^"; got != want {
			t.Errorf("rules[0].urlFilter = %q, want %q", got, want)
		}
		if got, want := rules[1].Condition.URLFilter, "||b.example^/x|"; got != want {
			t.Errorf("rules[1].urlFilter = %q, want %q", got, want)
		}

		// An empty snapshot is an empty (non-nil) JSON array, never null.
		empty := RulesetRules(&RulesetView{Version: 1})
		if empty == nil || len(empty) != 0 {
			t.Errorf("empty snapshot = %v, want a non-nil empty slice", empty)
		}
	})

	t.Run("corrupted entries are dropped instead of served over-broad", func(t *testing.T) {
		view := &RulesetView{Entries: []models.RulesetEntry{
			{URL: "https://good.example/", Verdict: models.VerdictMalicious},
			{URL: "%zz", Verdict: models.VerdictMalicious},           // unparseable
			{URL: "no-host-here", Verdict: models.VerdictSuspicious}, // hostless
		}}
		rules := RulesetRules(view)
		if len(rules) != 1 || rules[0].Condition.URLFilter != "||good.example^" {
			t.Errorf("rules = %+v, want exactly the healthy rule", rules)
		}
		if rules[0].ID == nil || *rules[0].ID != 1 {
			t.Errorf("the delivered rule is renumbered over what is shipped, id %v", rules[0].ID)
		}
	})

	t.Run("data.rule exists only for confirmed threats and carries no id", func(t *testing.T) {
		malicious, suspicious, clean, unknown := models.VerdictMalicious, models.VerdictSuspicious,
			models.VerdictNoThreat, models.VerdictUnknown
		hostile := &models.Submission{
			URL:    "https://hostile.example/download",
			Status: models.StatusCompleted, Finished: true,
			Verdict: &malicious,
		}
		rule := DNRRuleFor(hostile)
		if rule == nil {
			t.Fatal("a completed malicious assessment has no rule")
		}
		if rule.ID != nil {
			t.Errorf("the single-URL rule carries an id %d; the client assigns one", *rule.ID)
		}
		if rule.Condition.URLFilter != "||hostile.example^/download|" {
			t.Errorf("rule = %+v, want the exact-match filter", rule)
		}

		hostile.Verdict = &suspicious
		if DNRRuleFor(hostile) == nil {
			t.Error("a confirmed suspicious assessment must also get a rule")
		}
		hostile.Verdict = &clean
		if DNRRuleFor(hostile) != nil {
			t.Error("a clean assessment must not get a rule")
		}
		hostile.Verdict = &unknown
		if DNRRuleFor(hostile) != nil {
			t.Error("an unknown verdict must never become a rule")
		}
		hostile.Status = models.StatusPending
		hostile.Verdict = &malicious
		if DNRRuleFor(hostile) != nil {
			t.Error("a pending record must not get a rule")
		}
		if DNRRuleFor(nil) != nil {
			t.Error("nil input must not get a rule")
		}
	})
}
