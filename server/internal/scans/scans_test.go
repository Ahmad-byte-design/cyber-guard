package scans_test

import (
	"context"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"cyberguard/server/internal/memstore"
	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/providers/mock"
	"cyberguard/server/internal/scans"
	"cyberguard/server/internal/urlintel"
	"cyberguard/server/internal/verdicts"
)

// End-to-end tests for the scan lifecycle.
//
// Everything runs against the in-memory store and queue and the mock provider.
// No test contacts Hybrid Analysis or any external service, and none asserts
// against a fabricated verdict: each case drives the real state machine and
// checks what was persisted.

var testKey = []byte("0123456789abcdef0123456789abcdef")

type harness struct {
	svc      *scans.Service
	store    *memstore.Store
	queue    *memstore.Queue
	provider *mock.Provider
	logs     *strings.Builder
}

type harnessOptions struct {
	submit     func(context.Context, string) (providers.Submission, error)
	analysis   func(context.Context, string) (providers.Analysis, error)
	noProvider bool
	// fastPoll shrinks the polling intervals so deadline tests finish quickly.
	fastPoll bool
	// pollDeadline overrides the deadline. Zero uses the default.
	pollDeadline time.Duration
}

func newHarness(t *testing.T, opts harnessOptions) *harness {
	t.Helper()

	store, err := memstore.NewStore(testKey)
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	queue := memstore.NewQueue()

	provider := mock.New()
	if opts.submit != nil {
		provider = mock.New(mock.WithSubmit(opts.submit))
	} else {
		provider = mock.New(mock.WithSubmit(func(_ context.Context, raw string) (providers.Submission, error) {
			return providers.Submission{
				ProviderScanID: "job-" + shortHash(raw),
				State:          providers.StateQueued,
			}, nil
		}))
	}
	if opts.analysis != nil {
		provider = mock.New(
			mock.WithSubmit(submitOrDefault(opts.submit)),
			mock.WithAnalysis(opts.analysis),
		)
	} else {
		provider = mock.New(
			mock.WithSubmit(submitOrDefault(opts.submit)),
			mock.WithAnalysis(func(_ context.Context, _ string) (providers.Analysis, error) {
				return providers.Analysis{
					Finished:       true,
					Classification: "malicious",
					ProviderState:  "SUCCESS",
					ReportedAt:     time.Now().UTC(),
				}, nil
			}),
		)
	}

	aead, err := mongostore.NewTransientURLCipher(testKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}

	logs := &strings.Builder{}
	pollInterval := 5 * time.Millisecond
	pollDeadline := 400 * time.Millisecond
	if !opts.fastPoll {
		pollInterval = time.Second
		pollDeadline = 30 * time.Second
	}
	if opts.pollDeadline > 0 {
		pollDeadline = opts.pollDeadline
	}

	svcOpts := scans.Options{
		Store:           store,
		Queue:           queue,
		Provider:        provider,
		Cipher:          aead,
		Logger:          slog.New(slog.NewTextHandler(logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
		FingerprintKey:  testKey,
		AssessmentTTL:   time.Hour,
		TransientURLTTL: 10 * time.Minute,
		MaxAttempts:     3,
		ProviderTimeout: 5 * time.Second,
		PollInterval:    pollInterval,
		PollDeadline:    pollDeadline,
		Concurrency:     2,
		ClaimBlock:      10 * time.Millisecond,
	}
	if opts.noProvider {
		svcOpts.Provider = nil
	}

	svc, err := scans.New(svcOpts)
	if err != nil {
		t.Fatalf("scans.New: %v", err)
	}
	return &harness{svc: svc, store: store, queue: queue, provider: provider, logs: logs}
}

func submitOrDefault(fn func(context.Context, string) (providers.Submission, error)) mock.SubmitFunc {
	if fn != nil {
		return fn
	}
	return func(_ context.Context, raw string) (providers.Submission, error) {
		return providers.Submission{
			ProviderScanID: "job-" + shortHash(raw),
			State:          providers.StateQueued,
		}, nil
	}
}

func (h *harness) submit(t *testing.T, rawURL string) scans.Outcome {
	t.Helper()
	outcome, err := h.svc.Submit(t.Context(), rawURL)
	if err != nil {
		t.Fatalf("Submit: %v", err)
	}
	return outcome
}

func (h *harness) submitAndRun(t *testing.T, rawURL string) scans.Outcome {
	t.Helper()
	outcome := h.submit(t, rawURL)
	h.svc.Process(t.Context(), outcome.Scan.ScanID)
	return outcome
}

func (h *harness) scan(t *testing.T, id string) mongostore.Scan {
	t.Helper()
	scan, err := h.store.GetScan(t.Context(), id)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	return scan
}

// age moves a scan's updated_at into the past, so ListStalledScans returns it.
func (h *harness) age(t *testing.T, id string) {
	t.Helper()
	scan, err := h.store.GetScan(t.Context(), id)
	if err != nil {
		t.Fatalf("GetScan: %v", err)
	}
	scan.UpdatedAt = time.Now().Add(-time.Hour)
	h.store.PutScanDirect(scan)
}

func fingerprintOf(t *testing.T, raw string) string {
	t.Helper()
	_, fp, err := urlintel.Prepare(testKey, raw)
	if err != nil {
		t.Fatalf("fingerprint %q: %v", raw, err)
	}
	return fp
}

func cipherFor(t *testing.T) cipher.AEAD {
	t.Helper()
	aead, err := mongostore.NewTransientURLCipher(testKey)
	if err != nil {
		t.Fatalf("cipher: %v", err)
	}
	return aead
}

func shortHash(s string) string {
	var h uint64 = 14695981039346656037
	for i := range len(s) {
		h ^= uint64(s[i])
		h *= 1099511628211
	}
	return fmt.Sprintf("%016x", h)
}

// ------------------------------------------------------------- happy path

// A submission is accepted, encrypted, queued, analysed and cached.
func TestSubmitThenProcessProducesAVerdict(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	outcome := h.submitAndRun(t, "https://example.test/login")

	if !outcome.Created || !outcome.Enqueued {
		t.Fatalf("created=%v enqueued=%v, want both true", outcome.Created, outcome.Enqueued)
	}

	scan := h.scan(t, outcome.Scan.ScanID)
	if scan.Status != mongostore.ScanCompleted {
		t.Fatalf("status = %q, want completed", scan.Status)
	}
	if scan.ProviderScanID == "" {
		t.Error("the provider job id was not recorded on the scan")
	}
	if scan.LastErrorCode != "" {
		t.Errorf("a completed scan carries error code %q", scan.LastErrorCode)
	}

	// The URL must be gone the moment the submission was attempted.
	if n := h.store.TransientCount(); n != 0 {
		t.Errorf("%d encrypted URLs remain after submission, want 0", n)
	}

	result, err := h.svc.Lookup(t.Context(), outcome.Scan.ScanID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Assessment == nil {
		t.Fatal("a completed scan has no assessment")
	}
	if result.Assessment.Verdict != verdicts.Malicious {
		t.Errorf("verdict = %q, want malicious", result.Assessment.Verdict)
	}
	if len(result.Assessment.Evidence) == 0 {
		t.Error("no evidence was recorded for a completed analysis")
	}
	// Evidence reaches the browser extension verbatim, so it must be composed
	// from CyberGuard's own vocabulary rather than provider prose.
	for _, e := range result.Assessment.Evidence {
		if strings.Contains(e.Summary, "malicious") && strings.Contains(e.Summary, "SUCCESS") {
			continue
		}
		t.Errorf("unexpected evidence summary %q", e.Summary)
	}
}

// The URL is stored encrypted, never in the clear, and round-trips intact.
func TestTransientURLIsEncrypted(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	const target = "https://secret.example.test/pay?token=abc123"

	outcome := h.submit(t, target)

	ciphertext, ok := h.store.CiphertextFor(outcome.Scan.ScanID)
	if !ok {
		t.Fatal("no encrypted URL was stored")
	}
	for _, leak := range []string{"abc123", "secret.example.test", target} {
		if strings.Contains(ciphertext, leak) {
			t.Fatalf("the stored ciphertext contains %q: %q", leak, ciphertext)
		}
	}

	raw, err := h.store.GetTransientURL(t.Context(), cipherFor(t), outcome.Scan.ScanID)
	if err != nil {
		t.Fatalf("GetTransientURL: %v", err)
	}
	if raw != target {
		t.Errorf("round trip = %q, want %q", raw, target)
	}
}

// The scan record never carries the URL, only host-level intelligence.
func TestScanRecordCarriesNoRawURL(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	const target = "https://login.example.test/verify?token=s3cr3tvalue"
	outcome := h.submit(t, target)

	scan := h.scan(t, outcome.Scan.ScanID)

	// The hostname and registrable domain are retained deliberately: they are
	// the keys host- and domain-level reputation is aggregated on, and the
	// data model records them as accepted. What must never appear is anything
	// that identifies a specific resource or session.
	if scan.Hostname != "login.example.test" {
		t.Errorf("hostname = %q, want login.example.test", scan.Hostname)
	}
	if scan.RegistrableDomain != "example.test" {
		t.Errorf("registrable domain = %q, want example.test", scan.RegistrableDomain)
	}
	if scan.URLFingerprint == "" {
		t.Error("the scan has no fingerprint")
	}

	// Assert on the serialised form, which is what a client could ever see.
	rendered, err := json.Marshal(scan)
	if err != nil {
		t.Fatalf("marshal scan: %v", err)
	}
	for _, leak := range []string{"s3cr3tvalue", "token=", "/verify"} {
		if strings.Contains(string(rendered), leak) {
			t.Errorf("the serialised scan contains %q: %s", leak, rendered)
		}
	}
}

// ---------------------------------------------------------------- caching

// A fresh verdict is served without a second provider submission.
func TestFreshCacheHitSkipsTheProvider(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	const target = "https://example.test/cached"

	h.submitAndRun(t, target)
	before := h.provider.SubmitCount()

	outcome := h.submit(t, target)
	if !outcome.Cached || outcome.Assessment == nil {
		t.Fatal("the second submission was not served from cache")
	}
	if got := h.provider.SubmitCount(); got != before {
		t.Errorf("provider submissions went from %d to %d; a cache hit must not submit", before, got)
	}
	if n := len(h.store.ScanSnapshot()); n != 1 {
		t.Errorf("%d scans exist, want 1: a cache hit must not create one", n)
	}
	if n := len(h.queue.Pending()); n != 1 {
		t.Errorf("%d jobs queued, want 1: a cache hit must not enqueue", n)
	}
}

// An expired verdict is not served as fresh.
func TestExpiredAssessmentIsNotServed(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	const target = "https://example.test/stale"
	h.submitAndRun(t, target)

	assessment, err := h.store.GetAssessmentByFingerprint(t.Context(), fingerprintOf(t, target))
	if err != nil {
		t.Fatalf("GetAssessmentByFingerprint: %v", err)
	}
	assessment.ExpiresAt = time.Now().Add(-time.Minute)
	h.store.PutAssessmentDirect(assessment)

	outcome := h.submit(t, target)
	if outcome.Cached {
		t.Error("an expired verdict was served as fresh")
	}
	if !outcome.Created {
		t.Error("a new scan was not created for the expired URL")
	}
}

// ----------------------------------------------------------- deduplication

// Repeated submissions for one URL share a single scan.
func TestDuplicateSubmissionsShareOneScan(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	const target = "https://example.test/dupe"

	first := h.submit(t, target)
	second := h.submit(t, target)

	if !first.Created {
		t.Fatal("the first submission did not create a scan")
	}
	if second.Created {
		t.Error("the second submission created a scan")
	}
	if second.Scan.ScanID != first.Scan.ScanID {
		t.Errorf("second scan id = %q, want %q", second.Scan.ScanID, first.Scan.ScanID)
	}
	if n := len(h.store.ScanSnapshot()); n != 1 {
		t.Errorf("%d scans exist, want 1", n)
	}
	// The losing request must not leave its unused encrypted URL behind.
	if n := h.store.TransientCount(); n != 1 {
		t.Errorf("%d encrypted URLs stored, want 1: the losing copy was not cleaned up", n)
	}
}

// Concurrent submissions produce exactly one scan, whatever the interleaving.
//
// Deduplication is enforced by the store's partial-unique equivalent, not by a
// read-then-write check, so this exercises the database guarantee rather than
// a lock the application happens to hold.
func TestConcurrentSubmissionsProduceOneScan(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	const target = "https://example.test/race"
	const n = 25

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		ids  = map[string]bool{}
		errs []error
	)

	for range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			outcome, err := h.svc.Submit(context.Background(), target)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				errs = append(errs, err)
				return
			}
			ids[outcome.Scan.ScanID] = true
		}()
	}
	wg.Wait()

	for _, err := range errs {
		t.Fatalf("concurrent Submit: %v", err)
	}
	if len(ids) != 1 {
		t.Errorf("got %d distinct scan ids, want 1", len(ids))
	}
	if got := len(h.store.ScanSnapshot()); got != 1 {
		t.Errorf("%d scan records, want 1", got)
	}
	// Only the winning request's URL survives; every loser cleaned up.
	if got := h.store.TransientCount(); got != 1 {
		t.Errorf("%d encrypted URLs stored, want 1", got)
	}
}

// ------------------------------------------------- queue failure recovery

// MongoDB records the scan, Redis refuses the enqueue. The submission is still
// accepted and the reconciler delivers it: a delivery failure is a delay, never
// a lost scan.
func TestEnqueueFailureIsRecoveredByTheReconciler(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	h.queue.FailEnqueue = errors.New("redis: connection refused")

	outcome, err := h.svc.Submit(t.Context(), "https://example.test/redis-down")
	if err != nil {
		t.Fatalf("Submit must still succeed when the enqueue fails: %v", err)
	}
	if !outcome.Created {
		t.Error("the scan was not created")
	}
	if outcome.Enqueued {
		t.Error("Enqueued = true although the enqueue failed")
	}
	if n := h.store.TransientCount(); n != 1 {
		t.Fatalf("%d encrypted URLs stored, want 1: the input must survive", n)
	}

	h.queue.FailEnqueue = nil
	h.age(t, outcome.Scan.ScanID)
	h.svc.Reconcile(t.Context())

	if n := len(h.queue.Pending()); n != 1 {
		t.Fatalf("%d jobs queued after recovery, want 1", n)
	}
	h.svc.Process(t.Context(), outcome.Scan.ScanID)
	if got := h.scan(t, outcome.Scan.ScanID).Status; got != mongostore.ScanCompleted {
		t.Errorf("status = %q, want completed after recovery", got)
	}
}

// A duplicate delivery for a finished scan changes nothing.
func TestDuplicateDeliveryForAFinishedScanIsANoOp(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	outcome := h.submitAndRun(t, "https://example.test/twice")
	before := h.provider.SubmitCount()

	h.svc.Process(t.Context(), outcome.Scan.ScanID)
	h.svc.Process(t.Context(), outcome.Scan.ScanID)

	if got := h.provider.SubmitCount(); got != before {
		t.Errorf("provider submissions went from %d to %d; a duplicate must not resubmit", before, got)
	}
	if got := h.scan(t, outcome.Scan.ScanID).Status; got != mongostore.ScanCompleted {
		t.Errorf("status = %q, want completed", got)
	}
}

// A worker that died before submitting is recovered and completed.
func TestStalledScanIsRecoveredAndCompleted(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	outcome := h.submit(t, "https://example.test/stalled")

	// The claimed job is lost; only MongoDB still holds the scan.
	h.queue.Drain()
	h.age(t, outcome.Scan.ScanID)

	h.svc.Reconcile(t.Context())
	if n := len(h.queue.Pending()); n != 1 {
		t.Fatalf("%d jobs re-enqueued, want 1", n)
	}
	h.svc.Process(t.Context(), outcome.Scan.ScanID)

	if got := h.scan(t, outcome.Scan.ScanID).Status; got != mongostore.ScanCompleted {
		t.Errorf("status = %q, want completed", got)
	}
	if got := h.provider.SubmitCount(); got != 1 {
		t.Errorf("provider submissions = %d, want exactly 1", got)
	}
}

// A scan past its retry budget is failed rather than retried forever.
func TestScanExhaustingItsBudgetIsFailed(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	outcome := h.submit(t, "https://example.test/hopeless")

	// Each recovery consumes an attempt, so the budget runs out on the tick
	// after the last one. The loop is bounded rather than a fixed count so it
	// asserts the outcome, not the arithmetic.
	for range 10 {
		if !h.scan(t, outcome.Scan.ScanID).Status.IsActive() {
			break
		}
		h.age(t, outcome.Scan.ScanID)
		h.svc.Reconcile(t.Context())
	}

	scan := h.scan(t, outcome.Scan.ScanID)
	if scan.Status != mongostore.ScanFailed {
		t.Fatalf("status = %q, want failed", scan.Status)
	}
	if scan.LastErrorCode != "attempts_exhausted" {
		t.Errorf("error code = %q, want attempts_exhausted", scan.LastErrorCode)
	}
}

// ------------------------------------------------------- provider failures

// No failure path may produce no_threat_detected.
//
// This is the central safety property of the whole pipeline: a scan that did
// not produce a trustworthy result must never be cached as clean.
func TestNoFailureBecomesNoThreatDetected(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		submit     func(context.Context, string) (providers.Submission, error)
		analysis   func(context.Context, string) (providers.Analysis, error)
		noProvider bool
	}{
		{
			name: "auth failure",
			submit: func(context.Context, string) (providers.Submission, error) {
				return providers.Submission{}, fmt.Errorf("401: %w", providers.ErrAuthFailed)
			},
		},
		{
			name: "not configured",
			submit: func(context.Context, string) (providers.Submission, error) {
				return providers.Submission{}, providers.ErrNotConfigured
			},
		},
		{
			name: "malformed response",
			submit: func(context.Context, string) (providers.Submission, error) {
				return providers.Submission{}, fmt.Errorf("bad json: %w", providers.ErrBadResponse)
			},
		},
		{
			name: "ambiguous timeout",
			submit: func(context.Context, string) (providers.Submission, error) {
				return providers.Submission{}, fmt.Errorf("deadline: %w", context.DeadlineExceeded)
			},
		},
		{
			name: "network unavailable",
			submit: func(context.Context, string) (providers.Submission, error) {
				return providers.Submission{}, fmt.Errorf("dial: %w", providers.ErrUnavailable)
			},
		},
		{
			name: "provider analysis errored",
			analysis: func(context.Context, string) (providers.Analysis, error) {
				return providers.Analysis{
					Finished:      true,
					ProviderState: "ERROR",
					ErrorType:     "ENVIRONMENT_FAILURE",
				}, nil
			},
		},
		{
			name: "provider partial success",
			analysis: func(context.Context, string) (providers.Analysis, error) {
				// A forged classification must not survive a failed state.
				return providers.Analysis{
					Finished:       true,
					ProviderState:  "PARTIAL_SUCCESS",
					Classification: "no specific threat",
				}, nil
			},
		},
		{
			name: "unrecognised verdict",
			analysis: func(context.Context, string) (providers.Analysis, error) {
				return providers.Analysis{
					Finished:       true,
					ProviderState:  "SUCCESS",
					Classification: "definitely-not-a-known-token",
				}, nil
			},
		},
		{
			name: "poll read failure",
			analysis: func(context.Context, string) (providers.Analysis, error) {
				return providers.Analysis{}, fmt.Errorf("dial: %w", providers.ErrUnavailable)
			},
		},
		{
			name:       "no provider configured at all",
			noProvider: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newHarness(t, harnessOptions{
				submit:     tc.submit,
				analysis:   tc.analysis,
				noProvider: tc.noProvider,
				fastPoll:   true,
			})
			target := "https://example.test/" + strings.ReplaceAll(tc.name, " ", "-")
			outcome := h.submitAndRun(t, target)

			for fp, v := range h.store.Verdicts() {
				if v == verdicts.NoThreatDetected {
					t.Fatalf("%s produced no_threat_detected for %s", tc.name, fp)
				}
			}

			scan := h.scan(t, outcome.Scan.ScanID)
			if scan.Status == mongostore.ScanFailed && scan.LastErrorCode == "" {
				t.Error("a failed scan carries no error code")
			}
			if scan.Status == mongostore.ScanCompleted && len(h.store.Verdicts()) == 0 {
				t.Error("a completed scan has no verdict")
			}
		})
	}
}

// A failed analysis is not cached: a transient outage must not freeze an
// "unknown" verdict for the whole freshness window.
func TestFailedAnalysisWritesNoAssessment(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{
		fastPoll: true,
		analysis: func(context.Context, string) (providers.Analysis, error) {
			return providers.Analysis{Finished: true, ProviderState: "ERROR", ErrorType: "BOOM"}, nil
		},
	})
	outcome := h.submitAndRun(t, "https://example.test/errored")

	if n := len(h.store.Verdicts()); n != 0 {
		t.Fatalf("%d assessments cached for a failed analysis, want 0", n)
	}
	scan := h.scan(t, outcome.Scan.ScanID)
	if scan.Status != mongostore.ScanFailed {
		t.Errorf("status = %q, want failed", scan.Status)
	}
	// The provider's own diagnostics are retained for the operator.
	if scan.ProviderErrorType != "BOOM" {
		t.Errorf("provider error type = %q, want BOOM", scan.ProviderErrorType)
	}
}

// An ambiguous submission is never retried: the request may already have been
// accepted upstream, and a second attempt would double-charge quota.
func TestAmbiguousSubmissionIsNotRetried(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	h := newHarness(t, harnessOptions{
		submit: func(context.Context, string) (providers.Submission, error) {
			attempts.Add(1)
			return providers.Submission{}, fmt.Errorf("timeout: %w", context.DeadlineExceeded)
		},
	})
	outcome := h.submitAndRun(t, "https://example.test/ambiguous")

	if got := attempts.Load(); got != 1 {
		t.Fatalf("the submission was attempted %d times, want exactly 1", got)
	}
	scan := h.scan(t, outcome.Scan.ScanID)
	if scan.LastErrorCode != "submission_outcome_unknown" {
		t.Errorf("error code = %q, want submission_outcome_unknown", scan.LastErrorCode)
	}
	if scan.ProviderScanID != "" {
		t.Errorf("a failed submission recorded a provider job id %q", scan.ProviderScanID)
	}
}

// A rate-limit refusal ends the scan so the client can re-request, rather than
// the worker resubmitting.
func TestRateLimitedSubmissionEndsTheScanWithoutResubmitting(t *testing.T) {
	t.Parallel()

	var attempts atomic.Int32
	h := newHarness(t, harnessOptions{
		submit: func(context.Context, string) (providers.Submission, error) {
			attempts.Add(1)
			return providers.Submission{}, fmt.Errorf("429: %w", providers.ErrRateLimited)
		},
	})
	outcome := h.submitAndRun(t, "https://example.test/ratelimited")

	if got := attempts.Load(); got != 1 {
		t.Fatalf("attempted %d submissions, want 1", got)
	}
	if got := h.scan(t, outcome.Scan.ScanID).LastErrorCode; got != "provider_rate_limited" {
		t.Errorf("error code = %q, want provider_rate_limited", got)
	}
}

// A worker that dies after the provider accepted resumes by polling the stored
// job id, never by submitting again.
//
// This is the single most valuable recovery in the system, and it exists only
// because the job id is persisted immediately after submission.
func TestRestartResumesPollingWithoutResubmitting(t *testing.T) {
	t.Parallel()

	var submits atomic.Int32
	var polls atomic.Int32
	release := make(chan struct{})

	h := newHarness(t, harnessOptions{
		fastPoll: true,
		submit: func(_ context.Context, _ string) (providers.Submission, error) {
			submits.Add(1)
			return providers.Submission{ProviderScanID: "job-abc", State: providers.StateQueued}, nil
		},
		analysis: func(_ context.Context, id string) (providers.Analysis, error) {
			if id != "job-abc" {
				t.Errorf("polled %q, want the stored job id", id)
			}
			if polls.Add(1) == 1 {
				// Report in-progress, then block so the context can be
				// cancelled mid-poll, simulating a worker crash.
				<-release
				return providers.Analysis{Finished: false, ProviderState: "IN_PROGRESS"}, nil
			}
			return providers.Analysis{
				Finished:       true,
				Classification: "malicious",
				ProviderState:  "SUCCESS",
				ReportedAt:     time.Now().UTC(),
			}, nil
		},
	})

	outcome := h.submit(t, "https://example.test/resume")

	ctx, cancel := context.WithCancel(t.Context())
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		h.svc.Process(ctx, outcome.Scan.ScanID)
	}()

	// Wait until the first poll has started, then simulate the crash.
	for polls.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	cancel()
	wg.Wait()

	if got := submits.Load(); got != 1 {
		t.Fatalf("provider submissions = %d, want 1", got)
	}
	scan := h.scan(t, outcome.Scan.ScanID)
	if !scan.Status.IsActive() {
		t.Fatalf("status = %q, want an active status after the crash", scan.Status)
	}
	if scan.ProviderScanID != "job-abc" {
		t.Fatalf("provider job id = %q, want job-abc to have survived", scan.ProviderScanID)
	}

	// Restart: the scan still holds the job id, so it polls rather than submits.
	h.age(t, outcome.Scan.ScanID)
	h.svc.Reconcile(t.Context())
	h.svc.Process(t.Context(), outcome.Scan.ScanID)

	if got := submits.Load(); got != 1 {
		t.Fatalf("provider submissions after restart = %d, want 1: the URL was resubmitted", got)
	}
	if got := h.scan(t, outcome.Scan.ScanID).Status; got != mongostore.ScanCompleted {
		t.Errorf("status = %q, want completed", got)
	}
}

// The poll deadline ends a scan that never reports, with no verdict.
func TestPollDeadlineEndsTheScanWithoutAVerdict(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{
		fastPoll:     true,
		pollDeadline: 150 * time.Millisecond,
		analysis: func(context.Context, string) (providers.Analysis, error) {
			return providers.Analysis{Finished: false, ProviderState: "IN_PROGRESS"}, nil
		},
	})
	outcome := h.submitAndRun(t, "https://example.test/forever")

	if n := len(h.store.Verdicts()); n != 0 {
		t.Fatalf("%d assessments cached for an unfinished analysis, want 0", n)
	}
	scan := h.scan(t, outcome.Scan.ScanID)
	if scan.Status != mongostore.ScanTimedOut {
		t.Errorf("status = %q, want timed_out", scan.Status)
	}
	if scan.LastErrorCode != "provider_poll_timeout" {
		t.Errorf("error code = %q, want provider_poll_timeout", scan.LastErrorCode)
	}
}

// A multi-poll analysis converges on the terminal report and caches the verdict.
func TestPollingContinuesUntilTerminal(t *testing.T) {
	t.Parallel()

	var polls atomic.Int32
	h := newHarness(t, harnessOptions{
		fastPoll: true,
		analysis: func(context.Context, string) (providers.Analysis, error) {
			if polls.Add(1) < 3 {
				return providers.Analysis{Finished: false, ProviderState: "IN_PROGRESS"}, nil
			}
			return providers.Analysis{
				Finished:       true,
				Classification: "no specific threat",
				ProviderState:  "SUCCESS",
				ReportedAt:     time.Now().UTC(),
			}, nil
		},
	})
	outcome := h.submitAndRun(t, "https://example.test/slow")

	if got := polls.Load(); got < 3 {
		t.Errorf("polled %d times, want at least 3", got)
	}
	if got := h.scan(t, outcome.Scan.ScanID).Status; got != mongostore.ScanCompleted {
		t.Errorf("status = %q, want completed", got)
	}
	// The one path that legitimately reaches no_threat_detected.
	if v := h.store.Verdicts()[fingerprintOf(t, "https://example.test/slow")]; v != verdicts.NoThreatDetected {
		t.Errorf("verdict = %q, want no_threat_detected", v)
	}
}

// ---------------------------------------------------------- input recovery

// A scan whose encrypted URL has vanished fails with a clear code and never a
// verdict. Re-analysing an unreadable URL is impossible, and inventing one
// would analyse something the user did not request.
func TestMissingTransientURLFailsTheScanWithoutAVerdict(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	outcome := h.submit(t, "https://example.test/gone")
	h.store.DropTransient(outcome.Scan.ScanID)

	h.svc.Process(t.Context(), outcome.Scan.ScanID)

	if n := len(h.store.Verdicts()); n != 0 {
		t.Fatalf("%d assessments written without input, want 0", n)
	}
	scan := h.scan(t, outcome.Scan.ScanID)
	if scan.Status != mongostore.ScanFailed {
		t.Errorf("status = %q, want failed", scan.Status)
	}
	if scan.LastErrorCode != "input_unavailable" {
		t.Errorf("error code = %q, want input_unavailable", scan.LastErrorCode)
	}
	if h.provider.SubmitCount() != 0 {
		t.Error("the provider was called without a URL")
	}
}

// A ciphertext that cannot be decrypted fails the scan rather than submitting
// whatever garbage the record now holds.
//
// This is what an encryption-key rotation looks like from the worker's side: the
// records on disk were sealed with the old key, so nothing is readable and
// nothing may be submitted. Re-analysing an unreadable URL is impossible, and
// guessing at one would analyse something the user did not request.
func TestUndecryptableTransientURLFailsTheScan(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	outcome := h.submit(t, "https://example.test/tampered")

	// A second service over the same store, holding a rotated key.
	rotated := make([]byte, 32)
	copy(rotated, "ffffffffffffffffffffffffffffffff")
	rotatedAEAD, err := mongostore.NewTransientURLCipher(rotated)
	if err != nil {
		t.Fatalf("rotated cipher: %v", err)
	}
	rotatedService, err := scans.New(scans.Options{
		Store:          h.store,
		Queue:          h.queue,
		Provider:       h.provider,
		Cipher:         rotatedAEAD,
		FingerprintKey: testKey,
	})
	if err != nil {
		t.Fatalf("rotated service: %v", err)
	}

	rotatedService.Process(t.Context(), outcome.Scan.ScanID)

	if n := len(h.store.Verdicts()); n != 0 {
		t.Fatalf("%d assessments written from an unreadable URL, want 0", n)
	}
	if got := h.scan(t, outcome.Scan.ScanID).LastErrorCode; got != "input_unavailable" {
		t.Errorf("error code = %q, want input_unavailable", got)
	}
	if h.provider.SubmitCount() != 0 {
		t.Error("the provider was called with a URL that could not be decrypted")
	}
}

// A transient MongoDB outage leaves the scan active for the reconciler rather
// than failing work the client was told was accepted.
func TestStoreOutageLeavesTheScanActiveForRecovery(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	outcome := h.submit(t, "https://example.test/mongo-blip")

	h.store.FailWrites = errors.New("mongodb: server selection timeout")
	h.svc.Process(t.Context(), outcome.Scan.ScanID)

	if scan := h.scan(t, outcome.Scan.ScanID); !scan.Status.IsActive() {
		t.Fatalf("status = %q, want an active status so the reconciler can retry", scan.Status)
	}

	h.store.FailWrites = nil
	h.age(t, outcome.Scan.ScanID)
	h.svc.Reconcile(t.Context())
	h.svc.Process(t.Context(), outcome.Scan.ScanID)

	if got := h.scan(t, outcome.Scan.ScanID).Status; got != mongostore.ScanCompleted {
		t.Errorf("status = %q after recovery, want completed", got)
	}
}

// --------------------------------------------------------------- shutdown

// Cancelling the context stops the worker without losing in-flight work.
func TestCancellationLeavesTheScanRecoverable(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{fastPoll: true})
	outcome := h.submit(t, "https://example.test/cancel")

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.svc.Run(ctx)
	}()

	// Let the worker pick the job up, then stop it.
	time.Sleep(30 * time.Millisecond)
	cancel()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}

	scan := h.scan(t, outcome.Scan.ScanID)
	if !scan.Status.IsActive() && scan.Status != mongostore.ScanCompleted {
		t.Errorf("status = %q; a cancelled worker must leave the scan active or completed", scan.Status)
	}
}

// Run drains the queue and completes the scan, with no external orchestration.
func TestRunConsumesTheQueue(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{fastPoll: true})
	outcome := h.submit(t, "https://example.test/drained")

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = h.svc.Run(ctx)
	}()

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if h.scan(t, outcome.Scan.ScanID).Status == mongostore.ScanCompleted {
			break
		}
		time.Sleep(2 * time.Millisecond)
	}
	cancel()
	<-done

	if got := h.scan(t, outcome.Scan.ScanID).Status; got != mongostore.ScanCompleted {
		t.Errorf("status = %q, want completed: the worker did not drain the queue", got)
	}
}

// --------------------------------------------------------------- lookup

// An in-flight scan carries no verdict at all, not an empty one.
func TestInFlightScanCarriesNoVerdict(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	outcome := h.submit(t, "https://example.test/pending")

	result, err := h.svc.Lookup(t.Context(), outcome.Scan.ScanID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Assessment != nil {
		t.Fatal("an in-flight scan returned an assessment")
	}
	if result.Scan.Status != mongostore.ScanQueued {
		t.Errorf("status = %q, want queued", result.Scan.Status)
	}
}

// A completed scan whose assessment has expired reports no verdict rather than
// a stale one.
func TestCompletedScanWithExpiredAssessmentHasNoVerdict(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	const target = "https://example.test/expired-verdict"
	outcome := h.submitAndRun(t, target)

	h.store.ExpireAssessment(fingerprintOf(t, target))

	result, err := h.svc.Lookup(t.Context(), outcome.Scan.ScanID)
	if err != nil {
		t.Fatalf("Lookup: %v", err)
	}
	if result.Assessment != nil {
		t.Error("an expired assessment was returned as if fresh")
	}
	if result.Scan.Status != mongostore.ScanCompleted {
		t.Errorf("status = %q, want completed", result.Scan.Status)
	}
}

// A job for a scan that no longer exists is dropped, not an error.
func TestJobWithNoScanRecordIsDropped(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	h.svc.Process(t.Context(), "scan_doesnotexist")
}

// -------------------------------------------------------- privacy in logs

// Neither the lifecycle nor the worker logs the submitted URL.
func TestLogsNeverCarryTheRawURL(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{})
	const target = "https://supersecret.example.test/pay?token=abc123"
	h.submitAndRun(t, target)

	out := h.logs.String()
	for _, leak := range []string{"supersecret.example.test", "abc123", "/pay"} {
		if strings.Contains(out, leak) {
			t.Errorf("logs leaked %q:\n%s", leak, out)
		}
	}
}

// A scan that fails without ever reading its input must still have that input
// deleted. Several failure paths end before the URL is read — a missing
// provider, a budget already spent — and leaving the record to the TTL would
// keep the last copy of a user's URL in the database for no reason.
func TestTerminalFailureDeletesTheEncryptedURL(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{noProvider: true})
	outcome := h.submit(t, "https://example.test/orphaned")

	if n := h.store.TransientCount(); n != 1 {
		t.Fatalf("%d encrypted URLs after submission, want 1", n)
	}

	h.svc.Process(t.Context(), outcome.Scan.ScanID)

	if got := h.scan(t, outcome.Scan.ScanID).Status; got != mongostore.ScanFailed {
		t.Fatalf("status = %q, want failed", got)
	}
	if n := h.store.TransientCount(); n != 0 {
		t.Errorf("%d encrypted URLs remain after a terminal failure, want 0", n)
	}
}

// The same applies when the failure is a permanent provider rejection.
func TestProviderRejectionDeletesTheEncryptedURL(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{
		submit: func(context.Context, string) (providers.Submission, error) {
			return providers.Submission{}, fmt.Errorf("401: %w", providers.ErrAuthFailed)
		},
	})
	outcome := h.submit(t, "https://example.test/rejected")

	h.svc.Process(t.Context(), outcome.Scan.ScanID)

	if got := h.scan(t, outcome.Scan.ScanID).Status; got != mongostore.ScanFailed {
		t.Fatalf("status = %q, want failed", got)
	}
	if n := h.store.TransientCount(); n != 0 {
		t.Errorf("%d encrypted URLs remain after a provider rejection, want 0", n)
	}
}

// A shutdown must not delete the URL: the scan is still active and the resumed
// run still needs it.
func TestCancellationKeepsTheEncryptedURL(t *testing.T) {
	t.Parallel()

	h := newHarness(t, harnessOptions{noProvider: true})
	outcome := h.submit(t, "https://example.test/still-needed")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	h.svc.Process(ctx, outcome.Scan.ScanID)

	if n := h.store.TransientCount(); n != 1 {
		t.Errorf("%d encrypted URLs after a cancelled run, want 1: the resumed scan needs it", n)
	}
}
