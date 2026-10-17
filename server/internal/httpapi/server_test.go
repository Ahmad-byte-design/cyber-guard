package httpapi

import (
	"bytes"
	"context"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/health"
	"cyberguard/server/internal/memstore"
	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/providers/mock"
	"cyberguard/server/internal/scans"
	"cyberguard/server/internal/urlintel"
	"cyberguard/server/internal/verdicts"
)

// testKey is the 32-byte fingerprint/encryption key used across the API tests.
//
// It is a literal rather than a random value so a failing test is
// reproducible, and so two runs of the suite fingerprint the same URL
// identically.
var testKey = []byte("0123456789abcdef0123456789abcdef")

// testConfig is the baseline configuration: both secrets present, no provider.
func testConfig(hmacKey string) config.Config {
	key := testKey
	if hmacKey == "k" {
		hmacKey = string(testKey)
	}
	return config.Config{
		HTTPAddr: ":0",
		// Matches the production default, so tests exercise the route surface
		// most deployments actually run. The disabled case is covered
		// explicitly in docs_test.go.
		APIDocsEnabled:         true,
		URLFingerprintHMACKey:  hmacKey,
		URLEncryptionKey:       key,
		ShutdownTimeout:        time.Second,
		WorkerPollInterval:     time.Second,
		HealthCheckTimeout:     time.Second,
		RateLimitPerMinute:     0, // disabled unless a test opts in
		FingerprintSubmitLimit: 0,
	}
}

// testRig holds everything a test needs to drive the API end to end.
type testRig struct {
	handler  http.Handler
	service  *scans.Service
	store    *memstore.Store
	queue    *memstore.Queue
	provider *mock.Provider
	logs     *bytes.Buffer
	cfg      config.Config
}

// newRig builds a fully wired handler backed by in-memory persistence, a
// mock provider and a real AES cipher.
//
// The pipeline is real: the same scans.Service, the same ordering, the same
// encryption. Only the databases are in-memory.
func newRig(t *testing.T, opts ...func(*testRig)) *testRig {
	t.Helper()

	logs := &bytes.Buffer{}
	logger := slog.New(slog.NewJSONHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	store, err := memstore.NewStore(testKey)
	if err != nil {
		t.Fatalf("build store: %v", err)
	}
	queue := memstore.NewQueue()
	provider := mock.New(mock.WithAnalysis(func(ctx context.Context, id string) (providers.Analysis, error) {
		return providers.Analysis{
			Finished:       true,
			Classification: "malicious",
			ProviderState:  "SUCCESS",
			ReportedAt:     time.Now().UTC(),
		}, nil
	}))

	rig := &testRig{store: store, queue: queue, provider: provider, logs: logs, cfg: testConfig("k")}
	rig.handler = rig.build(t, logger, nil)

	for _, opt := range opts {
		opt(rig)
	}
	return rig
}

// build assembles the handler. It is separate so a test can rebuild after
// mutating configuration.
func (r *testRig) build(t *testing.T, logger *slog.Logger, checker *health.Checker) http.Handler {
	t.Helper()

	var aead cipher.AEAD
	if len(r.cfg.URLEncryptionKey) >= 32 {
		built, err := mongostore.NewTransientURLCipher(r.cfg.URLEncryptionKey)
		if err != nil {
			t.Fatalf("cipher: %v", err)
		}
		aead = built
	}

	fixed := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	service, err := scans.New(scans.Options{
		Store:           r.store,
		Queue:           r.queue,
		Provider:        r.provider,
		Cipher:          aead,
		Logger:          logger,
		FingerprintKey:  []byte(r.cfg.URLFingerprintHMACKey),
		AssessmentTTL:   time.Hour,
		TransientURLTTL: 10 * time.Minute,
	})
	if err != nil {
		t.Fatalf("scan service: %v", err)
	}
	r.service = service
	return NewServer(Dependencies{
		Config: r.cfg,
		Logger: logger,
		Health: checker,
		Scans:  service,
		Now:    func() time.Time { return fixed },
	}).Handler()
}

// withConfig rebuilds the handler with modified configuration.
func (r *testRig) withConfig(t *testing.T, mutate func(*config.Config)) *testRig {
	t.Helper()
	logger := slog.New(slog.NewJSONHandler(r.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	mutate(&r.cfg)
	r.handler = r.build(t, logger, nil)
	return r
}

func newTestServer(t *testing.T, hmacKey string, logBuf *bytes.Buffer) http.Handler {
	t.Helper()
	return newTestServerWithHealth(t, hmacKey, logBuf, nil)
}

// newTestServerWithHealth builds the handler with an optional readiness
// checker, so tests can exercise the dependency-probe path without a live
// datastore.
func newTestServerWithHealth(t *testing.T, hmacKey string, logBuf *bytes.Buffer, checker *health.Checker) http.Handler {
	t.Helper()

	w := logBuf
	if w == nil {
		w = &bytes.Buffer{}
	}
	logger := slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelDebug}))

	store, err := memstore.NewStore(testKey)
	if err != nil {
		t.Fatalf("build store: %v", err)
	}
	rig := &testRig{store: store, queue: memstore.NewQueue(), logs: w, cfg: testConfig(hmacKey)}
	return rig.build(t, logger, checker)
}

// stubCheck is a health.Check whose result is fixed by the test.
type stubCheck struct{ err error }

func (s stubCheck) Ping(context.Context) error { return s.err }

func do(t *testing.T, h http.Handler, method, target, body, contentType string) *httptest.ResponseRecorder {
	t.Helper()
	var r *http.Request
	if body == "" {
		r = httptest.NewRequest(method, target, nil)
	} else {
		r = httptest.NewRequest(method, target, strings.NewReader(body))
	}
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	return rec
}

func TestHealthLive(t *testing.T) {
	t.Parallel()
	rec := do(t, newTestServer(t, "", nil), http.MethodGet, "/health/live", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /health/live = %d, want 200", rec.Code)
	}
}

// Readiness must fail while the fingerprint key is missing: that key is
// required for every exact-URL cache lookup the product depends on.
func TestHealthReadyReflectsFingerprintKey(t *testing.T) {
	t.Parallel()

	rec := do(t, newTestServer(t, "", nil), http.MethodGet, "/health/ready", "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("ready without key = %d, want 503", rec.Code)
	}

	rec = do(t, newTestServer(t, "k", nil), http.MethodGet, "/health/ready", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ready with key = %d, want 200", rec.Code)
	}
}

func TestCheckURLRejectsNonHTTPSchemes(t *testing.T) {
	t.Parallel()

	for _, bad := range []string{"javascript:alert(1)", "file:///etc/passwd", "ftp://x.test"} {
		body := `{"url":"` + bad + `"}`
		rec := do(t, newTestServer(t, "k", nil), http.MethodPost, "/api/v1/check-url", body, "application/json")
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("check-url(%q) = %d, want 422", bad, rec.Code)
		}
	}
}

func TestCheckURLRejectsEmbeddedCredentials(t *testing.T) {
	t.Parallel()
	rec := do(t, newTestServer(t, "k", nil), http.MethodPost, "/api/v1/check-url",
		`{"url":"https://user:pw@x.test/p"}`, "application/json")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("check-url with credentials = %d, want 422", rec.Code)
	}
}

func TestCheckURLRejectsMalformedBodies(t *testing.T) {
	t.Parallel()
	h := newTestServer(t, "k", nil)

	// Structurally broken payloads are 400.
	cases := []struct{ name, body, ct string }{
		{"truncated json", `{"url":`, "application/json"},
		{"unknown field", `{"url":"https://x.test","extra":1}`, "application/json"},
		{"empty body", ``, "application/json"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := do(t, h, http.MethodPost, "/api/v1/check-url", c.body, c.ct)
			if rec.Code != http.StatusBadRequest {
				t.Errorf("%s = %d, want 400", c.name, rec.Code)
			}
		})
	}
}

// A well-formed body whose url is absent parses fine but fails validation, so
// it is a 422 rather than a 400.
func TestCheckURLMissingFieldIsUnprocessable(t *testing.T) {
	t.Parallel()
	rec := do(t, newTestServer(t, "k", nil), http.MethodPost, "/api/v1/check-url", `{}`, "application/json")
	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing url field = %d, want 422", rec.Code)
	}
}

// A valid URL is accepted for asynchronous analysis.
//
// The critical properties are what the response must NOT contain: no verdict,
// because nothing has been analysed yet. A 202 that carried a verdict would let
// a client act on a result that does not exist.
func TestCheckURLValidInputIsAccepted(t *testing.T) {
	t.Parallel()

	rec := do(t, newTestServer(t, "k", nil), http.MethodPost, "/api/v1/check-url",
		`{"url":"https://example.test/login"}`, "application/json")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("check-url valid = %d, want 202; body %s", rec.Code, rec.Body.String())
	}

	var body pendingAssessmentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if body.ScanID == "" {
		t.Error("202 body carries no scan_id")
	}
	if body.Cached {
		t.Error("cached = true on a first submission")
	}
	if body.Status != "queued" {
		t.Errorf("status = %q, want queued", body.Status)
	}
	if body.StatusURL != getURLPathPrefix+body.ScanID {
		t.Errorf("status_url = %q, want %q", body.StatusURL, getURLPathPrefix+body.ScanID)
	}
	if body.Retrying != nil {
		t.Error("retrying must be absent on a first submission, not false")
	}
	if strings.Contains(rec.Body.String(), "verdict") {
		t.Error("a 202 body must not contain a verdict: nothing has been analysed")
	}
	if rec.Header().Get("X-Request-ID") == "" {
		t.Error("response is missing a request_id")
	}
}

// A fresh cached verdict is returned as 200 and costs no provider call.
func TestCheckURLReturnsFreshCacheHit(t *testing.T) {
	t.Parallel()

	rig := newRig(t)
	body := `{"url":"https://example.test/login"}`

	first := do(t, rig.handler, http.MethodPost, "/api/v1/check-url", body, "application/json")
	if first.Code != http.StatusAccepted {
		t.Fatalf("first submission = %d, want 202", first.Code)
	}

	var pending pendingAssessmentResponse
	if err := json.Unmarshal(first.Body.Bytes(), &pending); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// Complete the scan the way the worker would.
	rig.store.PutAssessmentDirect(mongostore.Assessment{
		URLFingerprint: fingerprintOf(t, "https://example.test/login"),
		ScanID:         pending.ScanID,
		Verdict:        verdicts.Malicious,
		AnalyzedAt:     time.Now().UTC(),
		ExpiresAt:      time.Now().Add(time.Hour),
	})

	second := do(t, rig.handler, http.MethodPost, "/api/v1/check-url", body, "application/json")
	if second.Code != http.StatusOK {
		t.Fatalf("cache hit = %d, want 200; body %s", second.Code, second.Body.String())
	}

	var cached cachedAssessmentResponse
	if err := json.Unmarshal(second.Body.Bytes(), &cached); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !cached.Cached {
		t.Error("cached = false on a cache hit")
	}
	if cached.Verdict != "malicious" {
		t.Errorf("verdict = %q, want malicious", cached.Verdict)
	}
	if cached.ScanID != pending.ScanID {
		t.Errorf("scan_id = %q, want the scan that produced the verdict", cached.ScanID)
	}
	if len(rig.queue.Pending()) != 1 {
		t.Error("a cache hit must not enqueue further work")
	}
}

// Two concurrent submissions for the same URL produce exactly one scan, so one
// provider submission is made however many clients ask.
func TestCheckURLDeduplicatesConcurrentSubmissions(t *testing.T) {
	t.Parallel()

	rig := newRig(t)
	const n = 12
	body := `{"url":"https://example.test/race"}`

	codes := make(chan int, n)
	for range n {
		go func() {
			rec := do(t, rig.handler, http.MethodPost, "/api/v1/check-url", body, "application/json")
			codes <- rec.Code
		}()
	}

	seen := make(map[string]bool)
	for range n {
		rec := do(t, rig.handler, http.MethodPost, "/api/v1/check-url", body, "application/json")
		if rec.Code != http.StatusAccepted {
			t.Fatalf("status = %d, want 202", rec.Code)
		}
		var p pendingAssessmentResponse
		if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
			t.Fatalf("decode: %v", err)
		}
		seen[p.ScanID] = true
	}
	for range n {
		if c := <-codes; c != http.StatusAccepted {
			t.Fatalf("concurrent status = %d, want 202", c)
		}
	}

	if len(seen) != 1 {
		t.Errorf("got %d distinct scan ids, want 1: dedup failed", len(seen))
	}
	if got := len(rig.store.ScanSnapshot()); got != 1 {
		t.Errorf("got %d scan records, want 1", got)
	}
}

// Private and loopback targets are refused before anything is stored, because
// submitting one would disclose an internal host to the sandbox.
func TestCheckURLRejectsDisallowedTargets(t *testing.T) {
	t.Parallel()

	for _, target := range []string{
		"http://127.0.0.1/admin",
		"http://localhost:8080/",
		"http://192.168.1.1/",
		"http://10.0.0.5/admin",
		"http://169.254.169.254/latest/meta-data/",
		"http://[::1]/",
		"http://printer.local/",
		"http://fileserver.internal/share",
		"http://intranet/",
		"http://0.0.0.0/",
	} {
		t.Run(target, func(t *testing.T) {
			rig := newRig(t)
			rec := do(t, rig.handler, http.MethodPost, "/api/v1/check-url",
				`{"url":"`+target+`"}`, "application/json")
			if rec.Code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422; body %s", rec.Code, rec.Body.String())
			}
			if got := len(rig.store.ScanSnapshot()); got != 0 {
				t.Errorf("a refused target left %d scan records", got)
			}
			if rig.store.TransientCount() != 0 {
				t.Error("a refused target left an encrypted URL behind")
			}
			if len(rig.queue.Pending()) != 0 {
				t.Error("a refused target was enqueued")
			}
		})
	}
}

// A refused private target must not become an oracle for what is on the
// internal network: the detail names the class, never the address.
func TestCheckURLDisallowedDetailDoesNotEchoTheAddress(t *testing.T) {
	t.Parallel()

	rig := newRig(t)
	const target = "http://192.168.42.7/admin?token=s3cr3t"
	rec := do(t, rig.handler, http.MethodPost, "/api/v1/check-url",
		`{"url":"`+target+`"}`, "application/json")

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status = %d, want 422", rec.Code)
	}
	for _, leak := range []string{"192.168.42.7", "s3cr3t"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Errorf("response echoed %q:\n%s", leak, rec.Body.String())
		}
	}
}

// Without the HMAC key the service cannot fingerprint, so it must refuse
// rather than accept a URL it cannot later look up.
func TestCheckURLWithoutFingerprintKey(t *testing.T) {
	t.Parallel()
	rec := do(t, newTestServer(t, "", nil), http.MethodPost, "/api/v1/check-url",
		`{"url":"https://example.test/login"}`, "application/json")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("check-url without key = %d, want 503", rec.Code)
	}
}

func TestGetURLUnknownScanIs404(t *testing.T) {
	t.Parallel()
	rec := do(t, newTestServer(t, "k", nil), http.MethodGet, "/api/v1/get-url/scan_01ABC", "", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("get-url = %d, want 404", rec.Code)
	}
}

func TestRequestIDIsEchoed(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	r.Header.Set("X-Request-ID", "abc123")
	rec := httptest.NewRecorder()
	newTestServer(t, "k", nil).ServeHTTP(rec, r)

	if got := rec.Header().Get("X-Request-ID"); got != "abc123" {
		t.Errorf("X-Request-ID = %q, want abc123", got)
	}
}

// Architecture doc section 11: raw URLs must not appear in logs. This is the
// automated guard for that requirement.
func TestRawURLNeverReachesLogs(t *testing.T) {
	t.Parallel()
	buf := &bytes.Buffer{}
	h := newTestServer(t, "k", buf)

	const secretURL = "https://login.example.test/verify?token=s3cr3tvalue"

	rec := do(t, h, http.MethodPost, "/api/v1/check-url",
		`{"url":"`+secretURL+`"}`, "application/json")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}

	// The raw URL must appear in neither the logs nor the response body. The
	// response carries a scan id, which is the whole point of the fingerprint.
	out := buf.String()
	for _, leak := range []string{secretURL, "s3cr3tvalue", "login.example.test", "verify"} {
		if strings.Contains(out, leak) {
			t.Errorf("log output leaked %q:\n%s", leak, out)
		}
	}
	if strings.Contains(rec.Body.String(), "login.example.test") {
		t.Errorf("response body leaked the URL:\n%s", rec.Body.String())
	}
}

// The worker logs provider identifiers and statuses, never the submitted URL.
func TestWorkerLogsNeverCarryTheRawURL(t *testing.T) {
	t.Parallel()

	rig := newRig(t)
	body := `{"url":"https://secret.example.test/pay?token=abc123"}`
	rec := do(t, rig.handler, http.MethodPost, "/api/v1/check-url", body, "application/json")
	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202", rec.Code)
	}

	var pending pendingAssessmentResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &pending); err != nil {
		t.Fatalf("decode: %v", err)
	}

	rig.service.Process(t.Context(), pending.ScanID)

	out := rig.logs.String()
	for _, leak := range []string{"secret.example.test", "abc123", "/pay"} {
		if strings.Contains(out, leak) {
			t.Errorf("worker logs leaked %q:\n%s", leak, out)
		}
	}
}

// A panic must become a 500 with a generic message, not a stack trace or a
// crash of the whole process, and must not leak the panic value to the client.
func TestPanicIsRecovered(t *testing.T) {
	t.Parallel()

	buf := &bytes.Buffer{}
	s := NewServer(Dependencies{
		Logger: slog.New(slog.NewJSONHandler(buf, nil)),
	})
	h := s.recoverer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		panic("boom: secret-token-value")
	}))

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/boom", nil))

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "secret-token-value") {
		t.Errorf("panic value leaked to client: %s", rec.Body.String())
	}
	// The operator should still get the detail in the log.
	if !strings.Contains(buf.String(), "secret-token-value") {
		t.Errorf("panic value missing from logs:\n%s", buf.String())
	}
}

// Readiness must fail when a datastore is unreachable, because the service
// cannot do useful work without it.
func TestHealthReadyFailsWhenADependencyIsDown(t *testing.T) {
	t.Parallel()

	t.Run("all dependencies healthy", func(t *testing.T) {
		t.Parallel()
		checker := health.NewChecker(time.Second,
			health.Named{Name: "mongodb", Check: stubCheck{}},
			health.Named{Name: "provider_registry", Check: stubCheck{}},
		)
		rec := do(t, newTestServerWithHealth(t, "k", nil, checker), http.MethodGet, "/health/ready", "", "")
		if rec.Code != http.StatusOK {
			t.Fatalf("ready = %d, want 200; body %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("mongodb down", func(t *testing.T) {
		t.Parallel()
		checker := health.NewChecker(time.Second,
			health.Named{Name: "mongodb", Check: stubCheck{err: errors.New("dial refused")}},
			health.Named{Name: "provider_registry", Check: stubCheck{}},
		)
		rec := do(t, newTestServerWithHealth(t, "k", nil, checker), http.MethodGet, "/health/ready", "", "")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("ready with mongo down = %d, want 503", rec.Code)
		}
	})

	t.Run("a registered dependency is down", func(t *testing.T) {
		t.Parallel()
		// A dependency the readiness probe tracks. If it cannot be reached the
		// service must stop receiving traffic rather than answer "ready" while
		// unable to do the work it claims to be ready for.
		checker := health.NewChecker(time.Second,
			health.Named{Name: "mongodb", Check: stubCheck{}},
			health.Named{Name: "provider_registry", Check: stubCheck{err: errors.New("connection refused")}},
		)
		rec := do(t, newTestServerWithHealth(t, "k", nil, checker), http.MethodGet, "/health/ready", "", "")
		if rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("ready with a dependency down = %d, want 503", rec.Code)
		}
	})
}

// Readiness is served while liveness stays up, so a datastore outage does not
// make an orchestrator restart every replica.
func TestLivenessIgnoresDependencyOutage(t *testing.T) {
	t.Parallel()
	checker := health.NewChecker(time.Second,
		health.Named{Name: "mongodb", Check: stubCheck{err: errors.New("down")}},
	)
	h := newTestServerWithHealth(t, "k", nil, checker)

	if rec := do(t, h, http.MethodGet, "/health/live", "", ""); rec.Code != http.StatusOK {
		t.Errorf("live = %d, want 200 even when a dependency is down", rec.Code)
	}
	if rec := do(t, h, http.MethodGet, "/health/ready", "", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("ready = %d, want 503 when a dependency is down", rec.Code)
	}
}

// A missing provider key is a degraded sub-check, not a global failure: cached
// reads still work without a provider, so traffic should still be routed here.
func TestHealthReadyStaysOKWithoutProviderCredentials(t *testing.T) {
	t.Parallel()
	rec := do(t, newTestServer(t, "k", nil), http.MethodGet, "/health/ready", "", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("ready without provider key = %d, want 200", rec.Code)
	}

	var body struct {
		Status string `json:"status"`
		Checks []struct {
			Name string `json:"name"`
			OK   bool   `json:"ok"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	var sawProvider bool
	for _, c := range body.Checks {
		if c.Name == "provider" {
			sawProvider = true
			if c.OK {
				t.Error("provider check should report not-ok when the key is unset")
			}
		}
	}
	if !sawProvider {
		t.Error("readiness payload does not mention the provider check")
	}
}

// Every error response must be RFC 9457 with a stable code. Codes are the
// contract clients branch on, so this is asserted per endpoint rather than once.
func TestAllErrorsUseProblemDetails(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name, method, target, body, ct string
		wantStatus                     int
	}{
		{"check-url bad body", http.MethodPost, "/api/v1/check-url", `{"url":`, "application/json", http.StatusBadRequest},
		{"check-url bad scheme", http.MethodPost, "/api/v1/check-url", `{"url":"javascript:x"}`, "application/json", http.StatusUnprocessableEntity},
		{"check-url disallowed target", http.MethodPost, "/api/v1/check-url", `{"url":"http://127.0.0.1/"}`, "application/json", http.StatusUnprocessableEntity},
		{"get-url unknown", http.MethodGet, "/api/v1/get-url/scan_1", "", "", http.StatusNotFound},
		{"get-url malformed id", http.MethodGet, "/api/v1/get-url/%20", "", "", http.StatusBadRequest},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			rec := do(t, newTestServer(t, "k", nil), c.method, c.target, c.body, c.ct)
			if rec.Code != c.wantStatus {
				t.Fatalf("status = %d, want %d", rec.Code, c.wantStatus)
			}
			if got := rec.Header().Get("Content-Type"); !strings.HasPrefix(got, "application/problem+json") {
				t.Errorf("Content-Type = %q, want application/problem+json", got)
			}

			var p problem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("decode problem: %v", err)
			}
			if p.Code == "" || p.Title == "" || p.Type == "" {
				t.Errorf("incomplete problem detail: %+v", p)
			}
			if p.Status != c.wantStatus {
				t.Errorf("problem status = %d, want %d", p.Status, c.wantStatus)
			}
		})
	}
}

// fingerprintOf computes the fingerprint the service would use, so a test can
// seed a cache entry without duplicating the key handling.
func fingerprintOf(t *testing.T, raw string) string {
	t.Helper()
	_, fp, err := urlintel.Prepare(testKey, raw)
	if err != nil {
		t.Fatalf("fingerprint %q: %v", raw, err)
	}
	return fp
}
