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

	// injected failures
	findErr   error
	insertErr error
	updateErr error
	listErr   error

	// counters and traces
	inserts       int
	adopts        []string
	pendingSaves  int
	finalSaves    int
	resets        int
	inserted      []models.Submission
	duplicateSeen bool

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

func (m *memStore) ListSubmissions(ctx context.Context, page, limit int) ([]models.Submission, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.listErr != nil {
		return nil, 0, m.listErr
	}
	items := make([]models.Submission, 0, len(m.records))
	for _, rec := range m.records {
		items = append(items, *rec)
	}
	sort.Slice(items, func(i, j int) bool { return items[i].UpdatedAt.After(items[j].UpdatedAt) })
	total := int64(len(items))

	skip := (page - 1) * limit
	if skip >= len(items) {
		return []models.Submission{}, total, nil
	}
	end := skip + limit
	if end > len(items) {
		end = len(items)
	}
	return items[skip:end:end], total, nil
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
// listing
// ---------------------------------------------------------------------------

func TestList(t *testing.T) {
	fixed := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	newSub := func(i int) models.Submission {
		return models.Submission{
			URL: fmt.Sprintf("https://example.com/%d", i), Provider: models.ProviderName,
			ScanType: "all", Status: models.StatusPending,
			CreatedAt: fixed, UpdatedAt: fixed,
		}
	}

	t.Run("clamps defaults and maxima", func(t *testing.T) {
		store := &memStore{}
		store.seed(newSub(1))
		svc := New(store, nil, testOptions(time.Second, 10*time.Millisecond))

		_, pag, serr := svc.List(context.Background(), 0, 999)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if pag.Page != 1 || pag.Limit != MaxLimit {
			t.Errorf("pagination = %+v", pag)
		}
	})

	t.Run("empty collection", func(t *testing.T) {
		store := &memStore{}
		svc := New(store, nil, testOptions(time.Second, 10*time.Millisecond))

		items, pag, serr := svc.List(context.Background(), 1, 20)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if len(items) != 0 {
			t.Errorf("items = %d", len(items))
		}
		if pag.Total != 0 || pag.TotalPages != 0 {
			t.Errorf("pagination = %+v; an empty collection has zero pages", pag)
		}
	})

	t.Run("pagination math", func(t *testing.T) {
		store := &memStore{}
		store.seed(newSub(1))
		store.seed(newSub(2))
		svc := New(store, nil, testOptions(time.Second, 10*time.Millisecond))

		items, pag, serr := svc.List(context.Background(), 2, 1)
		if serr != nil {
			t.Fatalf("List: %+v", serr)
		}
		if len(items) != 1 {
			t.Errorf("items = %d", len(items))
		}
		if pag.Page != 2 || pag.Limit != 1 || pag.Total != 2 || pag.TotalPages != 2 {
			t.Errorf("pagination = %+v", pag)
		}
	})

	t.Run("store failure", func(t *testing.T) {
		store := &memStore{listErr: errors.New("find: connection closed")}
		svc := New(store, nil, testOptions(time.Second, 10*time.Millisecond))

		_, _, serr := svc.List(context.Background(), 1, 20)
		if serr == nil || serr.Code != CodeStoreUnavailable || serr.Status != 503 {
			t.Fatalf("got %+v, want store_unavailable/503", serr)
		}
	})
}
