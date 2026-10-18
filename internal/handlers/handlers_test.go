package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	apidocs "cyberguard/docs"
	"cyberguard/internal/config"
	"cyberguard/internal/hybridanalysis"
	"cyberguard/internal/models"
	"cyberguard/internal/services"
)

// ---- fakes (same contracts the real service depends on) ----

// fakeAnalyzer is the canned provider: QuickScanURL answers from submitErr /
// submitResult; GetQuickScanResult walks getSeq, repeating the last entry.
type fakeAnalyzer struct {
	calls  int
	gotURL string
	result hybridanalysis.Result
	err    error

	gets    int
	gotIDs  []string
	getSeq  []hybridanalysis.Result
	getIdx  int
	getErr  error
	getHook func(call int) error
}

func (f *fakeAnalyzer) QuickScanURL(ctx context.Context, rawURL string) (hybridanalysis.Result, error) {
	f.calls++
	f.gotURL = rawURL
	return f.result, f.err
}

func (f *fakeAnalyzer) GetQuickScanResult(ctx context.Context, quickScanID string) (hybridanalysis.Result, error) {
	f.gets++
	f.gotIDs = append(f.gotIDs, quickScanID)
	if f.getHook != nil {
		if err := f.getHook(f.gets); err != nil {
			return hybridanalysis.Result{}, err
		}
	}
	if f.getErr != nil {
		return hybridanalysis.Result{}, f.getErr
	}
	if len(f.getSeq) == 0 {
		return hybridanalysis.Result{ID: quickScanID}, nil
	}
	res := f.getSeq[f.getIdx]
	if f.getIdx < len(f.getSeq)-1 {
		f.getIdx++
	}
	return res, nil
}

// fakeStore implements the store contract with Mongo's guarantees, in memory.
type fakeStore struct {
	mu    sync.Mutex
	recs  []*models.Submission
	idSeq int

	findErr   error
	insertErr error
	updateErr error
	listErr   error

	items []models.Submission // canned list page
	total int64

	inserted []models.Submission
	saves    int
	resets   int

	finalSaveBlocked bool
	peerReadyVerdict string
}

func (f *fakeStore) seedLocked(sub models.Submission) {
	f.idSeq++
	sub.ID = bsonObjectID(f.idSeq)
	clone := sub
	f.recs = append(f.recs, &clone)
}

func (f *fakeStore) FindByURLHash(ctx context.Context, urlHash string) (*models.Submission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.findErr != nil {
		return nil, f.findErr
	}
	for _, rec := range f.recs {
		if rec.URLHash == urlHash {
			return rec, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) FindByRawURL(ctx context.Context, url string) (*models.Submission, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.findErr != nil {
		return nil, f.findErr
	}
	for _, rec := range f.recs {
		if rec.URL == url && rec.URLHash == "" {
			return rec, nil
		}
	}
	return nil, nil
}

func (f *fakeStore) AdoptURLHash(ctx context.Context, id bson.ObjectID, urlHash string) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return false, f.updateErr
	}
	for _, rec := range f.recs {
		if rec.ID == id && rec.URLHash == "" {
			rec.URLHash = urlHash
			return true, nil
		}
	}
	return false, nil
}

func (f *fakeStore) InsertSubmission(ctx context.Context, sub *models.Submission) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.insertErr != nil {
		return f.insertErr
	}
	for _, rec := range f.recs {
		if sub.URLHash != "" && rec.URLHash == sub.URLHash {
			return mongo.CommandError{Code: 11000, Message: "E11000 duplicate key error collection"}
		}
	}
	f.idSeq++
	sub.ID = bsonObjectID(f.idSeq)
	clone := *sub
	f.recs = append(f.recs, &clone)
	f.inserted = append(f.inserted, *sub)
	return nil
}

func (f *fakeStore) SavePendingProgress(ctx context.Context, id bson.ObjectID, stage *models.Submission) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return false, f.updateErr
	}
	f.saves++
	rec := f.byID(id)
	if rec == nil {
		return false, nil
	}
	if rec.IsCompleted() {
		return false, nil
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

func (f *fakeStore) SaveFinalResult(ctx context.Context, id bson.ObjectID, final *models.Submission) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return false, f.updateErr
	}
	f.saves++
	rec := f.byID(id)
	if rec == nil {
		return false, nil
	}
	if f.finalSaveBlocked {
		rec.Status = models.StatusCompleted
		rec.Finished = true
		v := f.peerReadyVerdict
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

func (f *fakeStore) ResetForRescan(ctx context.Context, id bson.ObjectID, expiredBefore time.Time, stage *models.Submission) (bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.updateErr != nil {
		return false, f.updateErr
	}
	f.resets++
	rec := f.byID(id)
	if rec == nil {
		return false, nil
	}
	if rec.IsCompleted() && !expiredBefore.After(rec.UpdatedAt) {
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

func (f *fakeStore) ListSubmissions(ctx context.Context, page, limit int) ([]models.Submission, int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.listErr != nil {
		return nil, 0, f.listErr
	}
	return f.items, f.total, nil
}

func (f *fakeStore) byID(id bson.ObjectID) *models.Submission {
	for _, rec := range f.recs {
		if rec.ID == id {
			return rec
		}
	}
	return nil
}

func (f *fakeStore) seed(sub models.Submission) *fakeStore {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seedLocked(sub)
	return f
}

func bsonObjectID(n int) bson.ObjectID {
	id, err := bson.ObjectIDFromHex(fmt.Sprintf("%024x", n))
	if err != nil {
		panic(err)
	}
	return id
}

// ---- test fixtures ----

func testConfig() config.Config {
	return config.Config{
		Port:               8080,
		MongoURI:           "mongodb://localhost:27017",
		MongoDatabase:      "cyberguard_test",
		HABaseURL:          "https://hybrid-analysis.com/api/v2",
		HAAPIKey:           "cfg-test-key",
		HATimeout:          30 * time.Second,
		HAScanType:         "all",
		AssessmentTTL:      24 * time.Hour,
		HAPollInterval:     time.Second,
		CORSAllowedOrigins: []string{"http://localhost:3000", "https://cyberguard.example"},
	}
}

func providerResult(finished bool) hybridanalysis.Result {
	return hybridanalysis.Result{
		ID:       "qs-1",
		SHA256:   "abc",
		ScanType: "all",
		Finished: finished,
		Scanners: []models.Scanner{{Name: "metadefender", Status: "no specific threat", StatusRaw: "NO_DETECTION", Progress: 100}},
		Reports:  []string{"r1"},
	}
}

func finishedV2Result(id string) hybridanalysis.Result {
	return hybridanalysis.Result{
		ID: id, SHA256: "abc", ScanType: "all", Finished: true,
		ScannersV2: map[string]any{
			"bfore_ai":     map[string]any{"status": "clean", "progress": 100},
			"scam_adviser": map[string]any{"status": "clean", "progress": 100},
		},
		Reports: []string{"r1"},
	}
}

func unfinishedV2Result(id string) hybridanalysis.Result {
	return hybridanalysis.Result{
		ID: id, ScanType: "all", Finished: false,
		ScannersV2: map[string]any{
			"bfore_ai": map[string]any{"status": "in-queue", "progress": 10},
		},
	}
}

// testServiceOptions keeps every wait inside milliseconds while remaining
// nonzero, so HTTP-level deadline paths run quickly.
func testServiceOptions() services.ServiceOptions {
	return services.ServiceOptions{AssessmentTTL: 24 * time.Hour, WaitBudget: 400 * time.Millisecond, PollInterval: 20 * time.Millisecond}
}

func newTestServerCfg(t *testing.T, analyzer services.URLAnalyzer, store *fakeStore, opts services.ServiceOptions) *httptest.Server {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	svc := services.New(store, analyzer, opts)

	cfg := testConfig()
	srv := httptest.NewServer(New(Dependencies{
		Config:  cfg,
		Logger:  logger,
		Service: svc,
	}).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func newTestServer(t *testing.T, analyzer services.URLAnalyzer, store *fakeStore) *httptest.Server {
	t.Helper()
	return newTestServerCfg(t, analyzer, store, testServiceOptions())
}

func postJSON(t *testing.T, url, body string) *http.Response {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, url, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { resp.Body.Close() })
	return resp
}

type envelope struct {
	Success    bool            `json:"success"`
	Message    string          `json:"message"`
	Data       json.RawMessage `json:"data"`
	Pagination *struct {
		Page       int   `json:"page"`
		Limit      int   `json:"limit"`
		Total      int64 `json:"total"`
		TotalPages int64 `json:"totalPages"`
	} `json:"pagination"`
	Error struct {
		Code   string `json:"code"`
		Status int    `json:"status"`
	} `json:"error"`
}

type submissionDTO struct {
	ID         string           `json:"id"`
	URL        string           `json:"url"`
	Provider   string           `json:"provider"`
	ProviderID string           `json:"providerId,omitempty"`
	SHA256     string           `json:"sha256,omitempty"`
	ScanType   string           `json:"scanType"`
	Status     string           `json:"status"`
	Finished   bool             `json:"finished"`
	Scanners   []map[string]any `json:"scanners,omitempty"`
	ScannersV2 map[string]any   `json:"scannersV2,omitempty"`
	Reports    []string         `json:"reports,omitempty"`
	Verdict    *string          `json:"verdict"`
	CreatedAt  string           `json:"createdAt"`
	UpdatedAt  string           `json:"updatedAt"`
}

func assertJSONError(t *testing.T, resp *http.Response, wantStatus int, wantCode string) envelope {
	t.Helper()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	var en envelope
	if err := json.Unmarshal(body, &en); err != nil {
		t.Fatalf("body is not JSON: %s", body)
	}
	if resp.StatusCode != wantStatus {
		t.Errorf("status = %d, want %d; body = %s", resp.StatusCode, wantStatus, body)
	}
	if en.Success {
		t.Errorf("success = true; body = %s", body)
	}
	if en.Error.Code != wantCode {
		t.Errorf("error.code = %q, want %q; body = %s", en.Error.Code, wantCode, body)
	}
	return en
}

// ---- POST /api/v1/check-url ----

func TestCheckURLSuccess(t *testing.T) {
	t.Run("provider finished in one round trip is HTTP 200", func(t *testing.T) {
		analyzer := &fakeAnalyzer{result: finishedV2Result("qs-1")}
		store := &fakeStore{}
		srv := newTestServer(t, analyzer, store)

		resp := postJSON(t, srv.URL+"/api/v1/check-url", `{"url":"https://example.com"}`)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d; body = %s", resp.StatusCode, body)
		}

		var en envelope
		if err := json.Unmarshal(body, &en); err != nil {
			t.Fatalf("not JSON: %s", body)
		}
		if !en.Success || en.Message != "URL analysis completed" {
			t.Fatalf("envelope = %+v (raw %s)", en, body)
		}

		var sub submissionDTO
		if err := json.Unmarshal(en.Data, &sub); err != nil {
			t.Fatalf("data is not a submission: %s", en.Data)
		}
		if sub.ID == "" {
			t.Error("data.id (the stored document id) is required in the response")
		}
		if sub.ProviderID != "qs-1" {
			t.Errorf("data.providerId = %q", sub.ProviderID)
		}
		if sub.URL != "https://example.com" {
			t.Errorf("data.url = %q", sub.URL)
		}
		if sub.Provider != models.ProviderName {
			t.Errorf("data.provider = %q", sub.Provider)
		}
		if !sub.Finished {
			t.Error("data.finished = false")
		}
		if sub.Status != models.StatusCompleted {
			t.Errorf("data.status = %q, want %q", sub.Status, models.StatusCompleted)
		}
		if sub.Verdict == nil || *sub.Verdict != models.VerdictNoThreat {
			t.Errorf("data.verdict = %v, want no_threat_detected", sub.Verdict)
		}
		if analyzer.calls != 1 {
			t.Errorf("provider calls = %d", analyzer.calls)
		}
		if len(store.inserted) != 1 {
			t.Errorf("stored = %d", len(store.inserted))
		}
	})

	t.Run("scan still running is HTTP 202 pending with a null verdict", func(t *testing.T) {
		analyzer := &fakeAnalyzer{
			result: unfinishedV2Result("qs-1"),
			getSeq: []hybridanalysis.Result{unfinishedV2Result("qs-1")},
		}
		store := &fakeStore{}
		srv := newTestServer(t, analyzer, store)

		resp := postJSON(t, srv.URL+"/api/v1/check-url", `{"url":"https://example.com"}`)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("status = %d; body = %s", resp.StatusCode, body)
		}

		var en envelope
		if err := json.Unmarshal(body, &en); err != nil {
			t.Fatalf("not JSON: %s", body)
		}
		if !en.Success || en.Message != "Analysis is still in progress" {
			t.Fatalf("envelope = %+v (raw %s)", en, body)
		}

		var sub submissionDTO
		if err := json.Unmarshal(en.Data, &sub); err != nil {
			t.Fatalf("data is not a submission: %s", en.Data)
		}
		if sub.Status != models.StatusPending {
			t.Errorf("data.status = %q, want %q", sub.Status, models.StatusPending)
		}
		if sub.Finished {
			t.Error("data.finished must carry the provider's own false")
		}
		if sub.Verdict != nil {
			t.Errorf("data.verdict = %v; a pending scan has no verdict", sub.Verdict)
		}
		if sub.ProviderID != "qs-1" {
			t.Errorf("data.providerId = %q", sub.ProviderID)
		}
		if analyzer.calls != 1 {
			t.Errorf("the same URL was submitted %d times while waiting", analyzer.calls)
		}
		if len(store.inserted) != 1 {
			t.Errorf("stored = %d", len(store.inserted))
		}
	})

	t.Run("a stored completed assessment is served without the provider", func(t *testing.T) {
		verdict := models.VerdictSuspicious
		fixed := time.Now().UTC()
		store := &fakeStore{}
		store.seed(models.Submission{
			URL: "https://example.com", Provider: models.ProviderName, ProviderID: "qs-old",
			ScanType: "all", Status: models.StatusCompleted, Finished: true,
			Verdict: &verdict, CreatedAt: fixed, UpdatedAt: fixed,
		})
		analyzer := &fakeAnalyzer{}
		srv := newTestServer(t, analyzer, store)

		resp := postJSON(t, srv.URL+"/api/v1/check-url", `{"url":"https://example.com"}`)
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d; body = %s", resp.StatusCode, body)
		}
		var en envelope
		if err := json.Unmarshal(body, &en); err != nil {
			t.Fatal(err)
		}
		var sub submissionDTO
		if err := json.Unmarshal(en.Data, &sub); err != nil {
			t.Fatal(err)
		}
		if analyzer.calls != 0 || analyzer.gets != 0 {
			t.Errorf("the provider was contacted for a cached result (submit=%d get=%d)", analyzer.calls, analyzer.gets)
		}
		if sub.Verdict == nil || *sub.Verdict != models.VerdictSuspicious {
			t.Errorf("the stored verdict was not served: %v", sub.Verdict)
		}
		if sub.ProviderID != "qs-old" {
			t.Errorf("data.providerId = %q", sub.ProviderID)
		}
	})
}

func TestCheckURLValidation(t *testing.T) {
	cases := []struct {
		name   string
		body   string
		status int
		code   string
	}{
		{"missing url field", `{"other":"x"}`, http.StatusUnprocessableEntity, services.CodeValidationError},
		{"empty url", `{"url":""}`, http.StatusUnprocessableEntity, services.CodeValidationError},
		{"unsupported scheme", `{"url":"ftp://example.com"}`, http.StatusUnprocessableEntity, services.CodeValidationError},
		{"no host", `{"url":"https://"}`, http.StatusUnprocessableEntity, services.CodeValidationError},
		{"not a scheme at all", `{"url":"example.com"}`, http.StatusUnprocessableEntity, services.CodeValidationError},
		{"malformed json", `{"url":`, http.StatusBadRequest, services.CodeInvalidRequest},
		{"not an object", `"just a string"`, http.StatusBadRequest, services.CodeInvalidRequest},
		{"unknown field", `{"url":"https://example.com","cheeky":1}`, http.StatusBadRequest, services.CodeInvalidRequest},
		{"oversized body", `{}` + strings.Repeat(" ", 9000), http.StatusBadRequest, services.CodeInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analyzer := &fakeAnalyzer{}
			store := &fakeStore{}
			srv := newTestServer(t, analyzer, store)

			resp := postJSON(t, srv.URL+"/api/v1/check-url", tc.body)
			assertJSONError(t, resp, tc.status, tc.code)

			if analyzer.calls != 0 {
				t.Errorf("the provider must not be called for an invalid request (%d)", analyzer.calls)
			}
			if len(store.inserted) != 0 {
				t.Errorf("nothing must be stored for an invalid request (%d)", len(store.inserted))
			}
		})
	}
}

func TestCheckURLMissingContentType(t *testing.T) {
	srv := newTestServer(t, &fakeAnalyzer{}, &fakeStore{})
	resp, err := http.Post(srv.URL+"/api/v1/check-url", "text/plain", strings.NewReader(`{"url":"https://example.com"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assertJSONError(t, resp, http.StatusBadRequest, services.CodeInvalidRequest)
}

func TestCheckURLProviderErrors(t *testing.T) {
	cases := []struct {
		name       string
		err        error
		status     int
		code       string
		retryAfter string
	}{
		{
			name:   "invalid api key",
			err:    fmt.Errorf("status 401: %w", hybridanalysis.ErrAuth),
			status: http.StatusBadGateway,
			code:   services.CodeProviderAuth,
		},
		{
			name:   "rate limited",
			err:    &hybridanalysis.RateLimitError{RetryAfter: 90 * time.Second, Err: hybridanalysis.ErrRateLimited},
			status: http.StatusTooManyRequests,
			code:   services.CodeProviderRateLimit,
		},
		{
			name:   "timeout",
			err:    fmt.Errorf("submit: %w", hybridanalysis.ErrTimeout),
			status: http.StatusGatewayTimeout,
			code:   services.CodeProviderTimeout,
		},
		{
			name:   "provider rejected",
			err:    fmt.Errorf("status 400: %w", hybridanalysis.ErrValidation),
			status: http.StatusBadGateway,
			code:   services.CodeProviderRejected,
		},
		{
			name:   "bad response",
			err:    fmt.Errorf("decode: %w", hybridanalysis.ErrBadResponse),
			status: http.StatusBadGateway,
			code:   services.CodeProviderBadResp,
		},
		{
			name:   "unavailable",
			err:    fmt.Errorf("transport: %w", hybridanalysis.ErrUnavailable),
			status: http.StatusBadGateway,
			code:   services.CodeProviderUnavail,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			analyzer := &fakeAnalyzer{err: tc.err}
			store := &fakeStore{}
			srv := newTestServer(t, analyzer, store)

			resp := postJSON(t, srv.URL+"/api/v1/check-url", `{"url":"https://example.com"}`)
			assertJSONError(t, resp, tc.status, tc.code)

			if tc.err != nil && errors.Is(tc.err, hybridanalysis.ErrRateLimited) {
				if got := resp.Header.Get("Retry-After"); got != "90" {
					t.Errorf("Retry-After = %q, want 90", got)
				}
			}
			if len(store.inserted) != 0 {
				t.Error("provider errors must never be stored as results")
			}
		})
	}
}

func TestCheckURLWhenProviderNotConfigured(t *testing.T) {
	srv := newTestServer(t, nil, &fakeStore{})

	resp := postJSON(t, srv.URL+"/api/v1/check-url", `{"url":"https://example.com"}`)
	assertJSONError(t, resp, http.StatusServiceUnavailable, services.CodeProviderMissingKey)
}

func TestCheckURLStoreFailure(t *testing.T) {
	analyzer := &fakeAnalyzer{result: finishedV2Result("qs-1")}
	store := &fakeStore{insertErr: errors.New("insert: connection closed")}
	srv := newTestServer(t, analyzer, store)

	resp := postJSON(t, srv.URL+"/api/v1/check-url", `{"url":"https://example.com"}`)
	assertJSONError(t, resp, http.StatusServiceUnavailable, services.CodeStoreUnavailable)
}

func TestCheckURLMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t, nil, &fakeStore{})

	resp, err := http.Get(srv.URL + "/api/v1/check-url")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	en := assertJSONError(t, resp, http.StatusMethodNotAllowed, "method_not_allowed")
	_ = en
	if allow := resp.Header.Get("Allow"); allow != "POST" {
		t.Errorf("Allow = %q, want POST", allow)
	}
}

// ---- GET /api/v1/get-all ----

func TestGetAll(t *testing.T) {
	fixed := time.Date(2026, 10, 17, 10, 0, 0, 0, time.UTC)
	items := []models.Submission{
		{URL: "https://newest.example", Provider: models.ProviderName, ProviderID: "qs-3",
			ScanType: "all", Status: models.StatusPending, CreatedAt: fixed, UpdatedAt: fixed},
		{URL: "https://older.example", Provider: models.ProviderName, ProviderID: "qs-2",
			ScanType: "all", Status: models.StatusCompleted, Finished: true, CreatedAt: fixed.Add(-time.Minute), UpdatedAt: fixed.Add(-time.Minute)},
	}

	t.Run("returns stored items with pagination", func(t *testing.T) {
		srv := newTestServer(t, nil, &fakeStore{items: items, total: 2})

		resp, err := http.Get(srv.URL + "/api/v1/get-all?page=1&limit=20")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d; body = %s", resp.StatusCode, body)
		}

		var en envelope
		if err := json.Unmarshal(body, &en); err != nil {
			t.Fatalf("not JSON: %s", body)
		}
		if !en.Success || en.Pagination == nil {
			t.Fatalf("envelope = %+v", en)
		}
		if en.Pagination.Total != 2 || en.Pagination.TotalPages != 1 || en.Pagination.Limit != 20 {
			t.Errorf("pagination = %+v", en.Pagination)
		}

		var got []submissionDTO
		if err := json.Unmarshal(en.Data, &got); err != nil {
			t.Fatalf("data: %s", en.Data)
		}
		if len(got) != 2 {
			t.Fatalf("items = %d", len(got))
		}
		if got[0].ID == "" {
			t.Error("item id (the mongo document id) is required")
		}
		if got[0].URL != "https://newest.example" {
			t.Errorf("first item url = %q", got[0].URL)
		}
		if got[0].Verdict != nil {
			t.Error("verdict must be null, not invented")
		}
	})

	t.Run("empty collection", func(t *testing.T) {
		srv := newTestServer(t, nil, &fakeStore{items: []models.Submission{}})

		resp, err := http.Get(srv.URL + "/api/v1/get-all")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d; %s", resp.StatusCode, body)
		}
		if !strings.Contains(string(body), `"data":[]`) {
			t.Errorf("empty collection must read as an empty array, not null: %s", body)
		}
		if !strings.Contains(string(body), `"totalPages":0`) {
			t.Errorf("an empty collection has zero pages: %s", body)
		}
	})

	t.Run("store failure", func(t *testing.T) {
		srv := newTestServer(t, nil, &fakeStore{listErr: errors.New("find: closed")})

		resp, err := http.Get(srv.URL + "/api/v1/get-all")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		assertJSONError(t, resp, http.StatusServiceUnavailable, services.CodeStoreUnavailable)
	})

	t.Run("method not allowed", func(t *testing.T) {
		srv := newTestServer(t, nil, &fakeStore{})

		resp := postJSON(t, srv.URL+"/api/v1/get-all", `{}`)
		en := assertJSONError(t, resp, http.StatusMethodNotAllowed, "method_not_allowed")
		_ = en
	})
}

func TestGetAllPaginationValidation(t *testing.T) {
	cases := []struct {
		query string
		code  string
	}{
		{"?page=abc", services.CodeInvalidRequest},
		{"?limit=abc", services.CodeInvalidRequest},
		{"?page=0", services.CodeInvalidRequest},
		{"?limit=0", services.CodeInvalidRequest},
		{"?limit=101", services.CodeInvalidRequest},
		{"?page=-1", services.CodeInvalidRequest},
	}
	for _, tc := range cases {
		t.Run(tc.query, func(t *testing.T) {
			srv := newTestServer(t, nil, &fakeStore{items: []models.Submission{}})

			resp, err := http.Get(srv.URL + "/api/v1/get-all" + tc.query)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			assertJSONError(t, resp, http.StatusBadRequest, tc.code)
		})
	}
}

// ---- routing, CORS, health, docs ----

func TestUnknownPath(t *testing.T) {
	srv := newTestServer(t, nil, &fakeStore{})

	resp, err := http.Get(srv.URL + "/api/v9/missing")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assertJSONError(t, resp, http.StatusNotFound, "not_found")
}

func TestCORS(t *testing.T) {
	srv := newTestServer(t, &fakeAnalyzer{}, &fakeStore{})

	t.Run("allowed origin gets headers", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/get-all", nil)
		req.Header.Set("Origin", "http://localhost:3000")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "http://localhost:3000" {
			t.Errorf("ACAO = %q", got)
		}
	})

	t.Run("disallowed origin gets no headers", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/get-all", nil)
		req.Header.Set("Origin", "https://evil.example")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("ACAO leaked to a disallowed origin: %q", got)
		}
	})

	t.Run("preflight", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodOptions, srv.URL+"/api/v1/check-url", nil)
		req.Header.Set("Origin", "https://cyberguard.example")
		req.Header.Set("Access-Control-Request-Method", "POST")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusNoContent {
			t.Errorf("preflight status = %d, want 204", resp.StatusCode)
		}
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://cyberguard.example" {
			t.Errorf("ACAO = %q", got)
		}
		methods := resp.Header.Get("Access-Control-Allow-Methods")
		if !strings.Contains(methods, "POST") || !strings.Contains(methods, "GET") {
			t.Errorf("Allow-Methods = %q", methods)
		}
	})

	t.Run("no origin header means no cors processing", func(t *testing.T) {
		resp, err := http.Get(srv.URL + "/api/v1/get-all")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "" {
			t.Errorf("ACAO = %q without an Origin header", got)
		}
	})
}

func TestHealth(t *testing.T) {
	pingFails := func(ctx context.Context) error { return errors.New("connection refused") }
	pingOK := func(ctx context.Context) error { return nil }

	t.Run("live", func(t *testing.T) {
		srv := httptest.NewServer(New(Dependencies{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Ping: pingFails}).Handler())
		t.Cleanup(srv.Close)

		resp, err := http.Get(srv.URL + "/health/live")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("live status = %d", resp.StatusCode)
		}
	})

	t.Run("ready when mongo answers", func(t *testing.T) {
		srv := httptest.NewServer(New(Dependencies{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Ping: pingOK}).Handler())
		t.Cleanup(srv.Close)

		resp, err := http.Get(srv.URL + "/health/ready")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("ready status = %d", resp.StatusCode)
		}
	})

	t.Run("not ready when mongo fails", func(t *testing.T) {
		srv := httptest.NewServer(New(Dependencies{Logger: slog.New(slog.NewTextHandler(io.Discard, nil)), Ping: pingFails}).Handler())
		t.Cleanup(srv.Close)

		resp, err := http.Get(srv.URL + "/health/ready")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Errorf("ready status = %d, want 503", resp.StatusCode)
		}
	})
}

// ---- documentation endpoints ----

func TestOpenAPISpec(t *testing.T) {
	srv := newTestServer(t, nil, &fakeStore{})

	resp, err := http.Get(srv.URL + "/openapi.yaml")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "yaml") {
		t.Errorf("Content-Type = %q", ct)
	}
	// The served document is the committed document, byte for byte.
	if string(body) != string(apidocs.OpenAPISpec) {
		t.Error("the served contract differs from docs/openapi.yaml")
	}

	spec := string(body)
	for _, path := range []string{"/api/v1/check-url", "/api/v1/get-all"} {
		if !strings.Contains(spec, path+":") {
			t.Errorf("the contract does not document %s", path)
		}
	}
	// Both the completed (200) and the still-running (202) answers are
	// documented, as is the verdict vocabulary and the pending/completed
	// status distinction.
	for _, want := range []string{
		"200", "202", "422", "429", "502", "503", "504",
		"totalPages", "pagination",
		"pending", "completed",
		"no_threat_detected", "inconclusive", "unknown",
		"GET /quick-scan/{id}",
	} {
		if !strings.Contains(spec, want) {
			t.Errorf("the contract does not describe %q", want)
		}
	}
	// No credential of any kind may appear. The environment variable NAME is
	// documentation; a VALUE would be a leak.
	for _, forbidden := range []string{"Bearer ", "api-key: ", "password"} {
		if strings.Contains(spec, forbidden) {
			t.Errorf("the contract mentions %q", forbidden)
		}
	}
}

func TestSwaggerUI(t *testing.T) {
	srv := newTestServer(t, nil, &fakeStore{})

	resp, err := http.Get(srv.URL + "/docs/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusOK {
		t.Errorf("docs status = %d", resp.StatusCode)
	}
	if ct := resp.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
	page := string(body)
	for _, want := range []string{"swagger-ui-bundle.js", "assets/swagger-ui.css", `../openapi.yaml`, `id="swagger-ui"`} {
		if !strings.Contains(page, want) {
			t.Errorf("the page does not reference %q", want)
		}
	}
	// No external asset origins: the page renders with no network access.
	for _, bad := range []string{`src="http`, `href="http`} {
		if strings.Contains(page, bad) {
			t.Errorf("the page loads an asset from another origin (%q)", bad)
		}
	}

	// And the assets the page references are served.
	for _, asset := range []string{"swagger-ui.css", "swagger-ui-bundle.js", "swagger-ui-standalone-preset.js"} {
		resp, err := http.Get(srv.URL + "/docs/assets/" + asset)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Errorf("asset %s status = %d", asset, resp.StatusCode)
		}
	}

	// An unrecognised asset is a JSON 404, not Go's plain text.
	resp, err = http.Get(srv.URL + "/docs/assets/not-a-file.css")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	assertJSONError(t, resp, http.StatusNotFound, "not_found")
}

func TestXRequestIDPropagation(t *testing.T) {
	srv := newTestServer(t, nil, &fakeStore{items: []models.Submission{}})

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/get-all", nil)
	req.Header.Set("X-Request-ID", "website-correlation-id-42")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if got := resp.Header.Get("X-Request-ID"); got != "website-correlation-id-42" {
		t.Errorf("X-Request-ID = %q", got)
	}
}
