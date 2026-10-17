package hybridanalysis_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/providers/hybridanalysis"
	"cyberguard/server/internal/verdicts"
)

// testKey is a fake credential used only against httptest servers. It must
// never reach a real API.
const testKey = "test-key-not-real"

// recorded captures what the client actually sent, so tests can assert on the
// wire contract rather than trusting the implementation.
type recorded struct {
	path        string
	method      string
	apiKey      string
	contentType string
	form        url.Values
}

// newClient starts a fake provider and returns a client pointed at it, plus the
// slice of requests it received.
//
// Every test in this file runs against httptest. Nothing here contacts
// hybrid-analysis.com.
func newClient(t *testing.T, handler http.HandlerFunc, opts ...func(*hybridanalysis.Options)) (*hybridanalysis.Client, *[]recorded) {
	t.Helper()

	got := &[]recorded{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		_ = r.Body.Close()

		form, _ := url.ParseQuery(string(body))
		*got = append(*got, recorded{
			path:        r.URL.Path,
			method:      r.Method,
			apiKey:      r.Header.Get("api-key"),
			contentType: r.Header.Get("Content-Type"),
			form:        form,
		})
		handler(w, r)
	}))
	t.Cleanup(srv.Close)

	o := hybridanalysis.Options{
		BaseURL:    srv.URL,
		APIKey:     testKey,
		MaxRetries: 0,
		Timeout:    2 * time.Second,
		Logger:     slog.New(slog.NewJSONHandler(io.Discard, nil)),
		HTTPClient: srv.Client(),
		Sleep:      func(context.Context, time.Duration) error { return nil },
		Now:        func() time.Time { return time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC) },
	}
	for _, fn := range opts {
		fn(&o)
	}

	c, err := hybridanalysis.New(o)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c, got
}

func writeJSON(t *testing.T, w http.ResponseWriter, status int, body any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(body); err != nil {
		t.Errorf("encode: %v", err)
	}
}

// ------------------------------------------------------------------ config

func TestNewRequiresAPIKey(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"", "   ", "\t"} {
		if _, err := hybridanalysis.New(hybridanalysis.Options{APIKey: key}); !errors.Is(err, providers.ErrNotConfigured) {
			t.Errorf("New(APIKey=%q) error = %v, want ErrNotConfigured", key, err)
		}
	}
}

func TestNewDefaultsToWindows11Environment(t *testing.T) {
	t.Parallel()

	c, err := hybridanalysis.New(hybridanalysis.Options{APIKey: testKey})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.EnvironmentID() != 140 {
		t.Errorf("EnvironmentID = %d, want 140 (Windows 11 64 bit)", c.EnvironmentID())
	}
}

// ------------------------------------------------------------- submission

// The documented contract: POST /submit/url, form-urlencoded, required url and
// environment_id, success 201 with a job_id.
func TestSubmitURLUsesDocumentedContract(t *testing.T) {
	t.Parallel()

	var got recorded
	c, reqs := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusCreated, map[string]any{
			"job_id":         "job-123",
			"submission_id":  "sub-456",
			"environment_id": 140,
			"sha256":         "abc",
		})
	})

	sub, err := c.SubmitURL(t.Context(), "https://example.test/login")
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	if sub.ProviderScanID != "job-123" {
		t.Errorf("ProviderScanID = %q, want job-123", sub.ProviderScanID)
	}
	if sub.State != providers.StateQueued {
		t.Errorf("State = %q, want %q", sub.State, providers.StateQueued)
	}

	if len(*reqs) != 1 {
		t.Fatalf("made %d requests, want 1", len(*reqs))
	}
	got = (*reqs)[0]

	if got.method != http.MethodPost {
		t.Errorf("method = %s, want POST", got.method)
	}
	if got.path != "/submit/url" {
		t.Errorf("path = %s, want /submit/url", got.path)
	}
	if !strings.HasPrefix(got.contentType, "application/x-www-form-urlencoded") {
		t.Errorf("Content-Type = %q, want application/x-www-form-urlencoded", got.contentType)
	}
	if got.form.Get("url") != "https://example.test/login" {
		t.Errorf("url field = %q", got.form.Get("url"))
	}
	if got.form.Get("environment_id") != "140" {
		t.Errorf("environment_id = %q, want 140", got.form.Get("environment_id"))
	}
	if got.apiKey != testKey {
		t.Errorf("api-key header = %q", got.apiKey)
	}
}

// job_id is nullable in the specification, so a 201 without it is an error, not
// an empty handle a worker would then poll forever.
func TestSubmitURLRejectsResponseWithoutJobID(t *testing.T) {
	t.Parallel()

	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusCreated, map[string]any{"submission_id": "sub-456"})
	})

	_, err := c.SubmitURL(t.Context(), "https://example.test/login")
	if !errors.Is(err, providers.ErrBadResponse) {
		t.Errorf("error = %v, want ErrBadResponse", err)
	}
}

func TestSubmitURLRejectsEmptyURL(t *testing.T) {
	t.Parallel()

	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server must not be called for an empty URL")
	})
	if _, err := c.SubmitURL(t.Context(), "  "); !errors.Is(err, providers.ErrBadResponse) {
		t.Errorf("error = %v, want ErrBadResponse", err)
	}
}

// ---------------------------------------------------------------- polling

func TestGetAnalysisQueuedDoesNotFetchSummary(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if !strings.HasSuffix(r.URL.Path, "/state") {
			t.Errorf("unexpected request to %s while queued", r.URL.Path)
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"state": "IN_QUEUE"})
	})

	a, err := c.GetAnalysis(t.Context(), "job-123")
	if err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}
	if a.Finished {
		t.Error("IN_QUEUE reported as finished")
	}
	if calls.Load() != 1 {
		t.Errorf("made %d requests while queued, want 1", calls.Load())
	}
}

func TestGetAnalysisTerminalFetchesSummary(t *testing.T) {
	t.Parallel()

	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/state"):
			writeJSON(t, w, http.StatusOK, map[string]any{"state": "SUCCESS"})
		case strings.HasSuffix(r.URL.Path, "/summary"):
			writeJSON(t, w, http.StatusOK, map[string]any{
				"state": "SUCCESS", "verdict": "malicious", "threat_level": 5,
			})
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	a, err := c.GetAnalysis(t.Context(), "job-123")
	if err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}
	if !a.Finished {
		t.Error("SUCCESS reported as unfinished")
	}
	if a.Classification != "malicious" {
		t.Errorf("Classification = %q, want malicious", a.Classification)
	}
	if a.Failed() {
		t.Error("SUCCESS reported as failed")
	}
}

// A completed-but-errored analysis must not fetch a summary: doing so could
// only produce a verdict for a sample that failed to analyse.
func TestGetAnalysisErrorStateSkipsSummary(t *testing.T) {
	t.Parallel()

	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/state") {
			t.Errorf("fetched summary for a failed analysis: %s", r.URL.Path)
		}
		writeJSON(t, w, http.StatusOK, map[string]any{
			"state": "ERROR", "error_type": "ANALYSIS_FAILED", "error_origin": "sandbox",
		})
	})

	a, err := c.GetAnalysis(t.Context(), "job-123")
	if err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}
	if !a.Finished {
		t.Error("ERROR state should be finished — the analysis completed and failed")
	}
	if !a.Failed() {
		t.Error("ERROR state not reported as failed")
	}
	if a.Classification != "" {
		t.Errorf("failed analysis carried a classification %q; it must be empty", a.Classification)
	}
	if a.ErrorType != "ANALYSIS_FAILED" {
		t.Errorf("ErrorType = %q", a.ErrorType)
	}
}

// An unrecognised state must be surfaced verbatim, not coerced to a known one.
func TestGetAnalysisPassesThroughUnknownState(t *testing.T) {
	t.Parallel()

	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/state") {
			writeJSON(t, w, http.StatusOK, map[string]any{"state": "SOMETHING_NEW"})
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"state": "SOMETHING_NEW", "verdict": "malicious"})
	})

	a, err := c.GetAnalysis(t.Context(), "job-123")
	if err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}
	if a.ProviderState != "SOMETHING_NEW" {
		t.Errorf("ProviderState = %q, want the value passed through verbatim", a.ProviderState)
	}
	if a.Failed() {
		t.Error("an unknown state must not be treated as a known failure")
	}
}

func TestGetAnalysisRejectsEmptyScanID(t *testing.T) {
	t.Parallel()

	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		t.Error("server must not be called for an empty scan id")
	})
	if _, err := c.GetAnalysis(t.Context(), " "); !errors.Is(err, providers.ErrBadResponse) {
		t.Errorf("error = %v, want ErrBadResponse", err)
	}
}

// ------------------------------------------------------------------ quota

func TestGetQuotaReadsQuotaReached(t *testing.T) {
	t.Parallel()

	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/key/submission-quota" {
			t.Errorf("path = %s", r.URL.Path)
		}
		writeJSON(t, w, http.StatusOK, map[string]any{
			"detonation": map[string]any{"quota_reached": true},
			"quick_scan": map[string]any{"quota_reached": false},
		})
	})

	det, quick, err := c.GetQuota(t.Context())
	if err != nil {
		t.Fatalf("GetQuota: %v", err)
	}
	if !det {
		t.Error("detonation quota_reached = false, want true")
	}
	if quick {
		t.Error("quick_scan quota_reached = true, want false")
	}
}

// ----------------------------------------------------------------- errors

func TestStatusMapping(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status int
		want   error
	}{
		{"unauthorized", http.StatusUnauthorized, providers.ErrAuthFailed},
		{"forbidden", http.StatusForbidden, providers.ErrAuthFailed},
		{"rate limited", http.StatusTooManyRequests, providers.ErrRateLimited},
		{"gone", http.StatusGone, providers.ErrBadResponse},
		{"bad request", http.StatusBadRequest, providers.ErrBadResponse},
		{"server error", http.StatusInternalServerError, providers.ErrUnavailable},
		{"bad gateway", http.StatusBadGateway, providers.ErrUnavailable},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(`{"message":"provider prose"}`))
			})

			_, err := c.SubmitURL(t.Context(), "https://example.test/x")
			if !errors.Is(err, tc.want) {
				t.Errorf("status %d error = %v, want %v", tc.status, err, tc.want)
			}
		})
	}
}

// The specification declares no idempotency token, so an ambiguous submission
// failure must never be retried.
func TestSubmitURLIsNeverRetried(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := c.SubmitURL(t.Context(), "https://example.test/x")
	if !errors.Is(err, providers.ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("submission attempted %d times, want exactly 1", got)
	}
}

// A GET is idempotent, so it is safe to retry — and must be.
func TestGetAnalysisRetriesTransientFailures(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		writeJSON(t, w, http.StatusOK, map[string]any{"state": "IN_PROGRESS"})
	}, func(o *hybridanalysis.Options) {
		o.MaxRetries = 2
		o.RetryBase = time.Millisecond
	})

	a, err := c.GetAnalysis(t.Context(), "job-123")
	if err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}
	if a.Finished {
		t.Error("expected unfinished")
	}
	if got := calls.Load(); got != 2 {
		t.Errorf("made %d attempts, want 2 (one failure plus one retry)", got)
	}
}

// A permanent failure must not be retried, even when retries are enabled.
func TestGetAnalysisDoesNotRetryPermanentFailures(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}, func(o *hybridanalysis.Options) {
		o.MaxRetries = 3
		o.RetryBase = time.Millisecond
	})

	if _, err := c.GetAnalysis(t.Context(), "job-123"); !errors.Is(err, providers.ErrAuthFailed) {
		t.Errorf("error = %v, want ErrAuthFailed", err)
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("made %d attempts for a permanent failure, want 1", got)
	}
}

// Provider output is untrusted input; an unexpected shape is rejected rather
// than partially interpreted.
func TestMalformedResponseIsRejected(t *testing.T) {
	t.Parallel()

	cases := []struct{ name, body string }{
		{"not json", `<html>gateway error</html>`},
		{"wrong shape", `{"unexpected":true}`},
		{"empty", ``},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(tc.body))
			})

			if _, err := c.SubmitURL(t.Context(), "https://example.test/x"); err == nil {
				t.Error("malformed body accepted, want an error")
			}
		})
	}
}

// A hostile or broken provider must not be able to exhaust memory.
func TestOversizedResponseIsRejected(t *testing.T) {
	t.Parallel()

	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"job_id":"` + strings.Repeat("A", 64<<10) + `"}`))
	}, func(o *hybridanalysis.Options) { o.MaxBodyBytes = 1024 })

	_, err := c.SubmitURL(t.Context(), "https://example.test/x")
	if !errors.Is(err, providers.ErrBadResponse) {
		t.Errorf("error = %v, want ErrBadResponse for an oversized body", err)
	}
}

func TestContextCancellationIsHonoured(t *testing.T) {
	t.Parallel()

	release := make(chan struct{})
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		writeJSON(t, w, http.StatusCreated, map[string]any{"job_id": "j"})
	})
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
	defer cancel()

	_, err := c.SubmitURL(ctx, "https://example.test/x")
	if err == nil {
		t.Fatal("SubmitURL succeeded despite a cancelled context")
	}
}

// ---------------------------------------------------------------- verdicts

// The core safety property: no failure path can produce no_threat_detected.
func TestNormaliseVerdictNeverTreatsFailureAsNoThreatDetected(t *testing.T) {
	t.Parallel()

	failures := []providers.Analysis{
		{ProviderState: "ERROR", Finished: true, Classification: "no specific threat"},
		{ProviderState: "PARTIAL_SUCCESS", Finished: true, Classification: "whitelisted"},
		{ProviderState: "ERROR", Finished: true, Classification: ""},
		{ProviderState: "IN_PROGRESS", Finished: false, Classification: "malicious"},
		{ProviderState: "", Finished: false, Classification: "malicious"},
		{ProviderState: "SUCCESS", Finished: true, Classification: ""},
		{ProviderState: "SUCCESS", Finished: true, Classification: "totally-new-value"},
	}

	for i, a := range failures {
		if got := hybridanalysis.NormaliseVerdict(a); got == verdicts.NoThreatDetected {
			t.Errorf("case %d (%+v) normalised to no_threat_detected", i, a)
		}
		if got := hybridanalysis.NormaliseVerdict(a); got != verdicts.Unknown {
			t.Errorf("case %d (%+v) = %q, want unknown", i, a, got)
		}
	}
}

func TestNormaliseVerdictMapping(t *testing.T) {
	t.Parallel()

	// Only the five names documented in the POST /search/hash filter are
	// mapped. Everything else is unknown by design.
	cases := []struct {
		classification string
		want           verdicts.Verdict
	}{
		{"malicious", verdicts.Malicious},
		{"MALICIOUS", verdicts.Malicious},
		{"  malicious  ", verdicts.Malicious},
		{"suspicious", verdicts.Suspicious},
		{"no specific threat", verdicts.NoThreatDetected},
		{"whitelisted", verdicts.NoThreatDetected},
		{"no verdict", verdicts.Inconclusive},
		{"", verdicts.Unknown},
		{"clean", verdicts.Unknown},
		{"safe", verdicts.Unknown},
		{"unknown-value", verdicts.Unknown},

		// Deliberately near-misses. These are plausible-sounding values that
		// the specification does NOT document, so they must fall through to
		// unknown rather than being matched on a guess. If a live API turns
		// out to return one of them, the fix is to verify it against the
		// documentation and add it deliberately — not to pattern-match here.
		{"no specific threat detected", verdicts.Unknown},
		{"no_threat_detected", verdicts.Unknown},
		{"not suspicious", verdicts.Unknown},
		{"malicious ", verdicts.Malicious}, // trimming is applied
	}

	for _, tc := range cases {
		a := providers.Analysis{
			Finished:       true,
			ProviderState:  "SUCCESS",
			Classification: tc.classification,
		}
		if got := hybridanalysis.NormaliseVerdict(a); got != tc.want {
			t.Errorf("NormaliseVerdict(%q) = %q, want %q", tc.classification, got, tc.want)
		}
	}
}

func TestEnvironmentName(t *testing.T) {
	t.Parallel()

	if got := hybridanalysis.EnvironmentName(140); got != "Windows 11 64 bit" {
		t.Errorf("EnvironmentName(140) = %q", got)
	}
	if got := hybridanalysis.EnvironmentName(9999); got != "unknown" {
		t.Errorf("EnvironmentName(9999) = %q, want unknown", got)
	}
}

// ------------------------------------------------------------ secret hygiene

// No failure path may expose the API key, and no failure path may expose the
// submitted URL.
func TestSecretsAndURLsNeverLeak(t *testing.T) {
	t.Parallel()

	const submittedURL = "https://login.example.test/verify?token=s3cr3tvalue"

	var logBuf strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))

	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "auth failure",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"message":"invalid api-key ` + testKey + `"}`))
			},
		},
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				_, _ = w.Write([]byte(`{"message":"upstream saw ` + submittedURL + `"}`))
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logBuf.Reset()
			c, _ := newClient(t, tc.handler, func(o *hybridanalysis.Options) { o.Logger = logger })

			_, err := c.SubmitURL(t.Context(), submittedURL)
			if err == nil {
				t.Fatal("expected an error")
			}

			if strings.Contains(err.Error(), testKey) {
				t.Errorf("error leaked the API key: %v", err)
			}
			if strings.Contains(err.Error(), submittedURL) || strings.Contains(err.Error(), "s3cr3tvalue") {
				t.Errorf("error leaked the submitted URL: %v", err)
			}
			if strings.Contains(logBuf.String(), testKey) {
				t.Errorf("log leaked the API key: %s", logBuf.String())
			}
		})
	}
}

// The environment ID and job ID are safe to log; the URL is not.
func TestLogsCarryNoRawURL(t *testing.T) {
	t.Parallel()

	const submittedURL = "https://login.example.test/verify?token=s3cr3tvalue"

	var logBuf strings.Builder
	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusCreated, map[string]any{"job_id": "job-123"})
	}, func(o *hybridanalysis.Options) {
		o.Logger = slog.New(slog.NewJSONHandler(&logBuf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	})

	if _, err := c.SubmitURL(t.Context(), submittedURL); err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	if strings.Contains(logBuf.String(), submittedURL) || strings.Contains(logBuf.String(), "s3cr3tvalue") {
		t.Errorf("log leaked the submitted URL: %s", logBuf.String())
	}
	if !strings.Contains(logBuf.String(), "job-123") {
		t.Errorf("log is missing the provider scan id: %s", logBuf.String())
	}
}

// The API key must reach the provider but must never be echoed back by us.
func TestAPIKeySentButNotReturned(t *testing.T) {
	t.Parallel()

	c, _ := newClient(t, func(w http.ResponseWriter, r *http.Request) {
		writeJSON(t, w, http.StatusCreated, map[string]any{"job_id": "job-123"})
	})

	sub, err := c.SubmitURL(t.Context(), "https://example.test/x")
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}
	if strings.Contains(sub.ProviderScanID, testKey) {
		t.Error("the API key appeared in a returned value")
	}
}

// ------------------------------------------------------------------- misc

func TestBaseURLTrailingSlashIsNormalised(t *testing.T) {
	t.Parallel()

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"job_id":"j"}`))
	}))
	t.Cleanup(srv.Close)

	c, err := hybridanalysis.New(hybridanalysis.Options{
		BaseURL: srv.URL + "/",
		APIKey:  testKey,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if _, err := c.SubmitURL(t.Context(), "https://example.test/x"); err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}
	if gotPath != "/submit/url" {
		t.Errorf("path = %q, want /submit/url without a double slash", gotPath)
	}
}
