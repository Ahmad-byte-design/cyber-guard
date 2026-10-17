package mock

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"cyberguard/server/internal/providers"
)

func TestDefaultProviderSubmitsAndReports(t *testing.T) {
	t.Parallel()

	p := New()

	sub, err := p.SubmitURL(t.Context(), "https://example.test/login")
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}
	if sub.ProviderScanID == "" {
		t.Error("ProviderScanID is empty")
	}
	if sub.State != providers.StateQueued {
		t.Errorf("State = %q, want %q", sub.State, providers.StateQueued)
	}

	analysis, err := p.GetAnalysis(t.Context(), sub.ProviderScanID)
	if err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}
	if !analysis.Finished {
		t.Error("default analysis reports Finished=false")
	}
}

// A stable, distinct ID per URL is what lets a test assert that one fingerprint
// produced one submission.
func TestSubmitIDIsStableAndDistinct(t *testing.T) {
	t.Parallel()

	p := New()

	first, err := p.SubmitURL(t.Context(), "https://example.test/a")
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}
	again, err := p.SubmitURL(t.Context(), "https://example.test/a")
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}
	other, err := p.SubmitURL(t.Context(), "https://example.test/b")
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	if first.ProviderScanID != again.ProviderScanID {
		t.Error("same URL produced different scan IDs")
	}
	if first.ProviderScanID == other.ProviderScanID {
		t.Error("different URLs produced the same scan ID")
	}
}

// This is the assertion behind the "one fingerprint, one provider submission"
// guarantee described in docs/testing-strategy.md.
func TestSubmitCountTracksSubmissions(t *testing.T) {
	t.Parallel()

	p := New()
	if got := p.SubmitCount(); got != 0 {
		t.Fatalf("fresh provider SubmitCount = %d, want 0", got)
	}

	for i := 0; i < 3; i++ {
		if _, err := p.SubmitURL(t.Context(), "https://example.test/x"); err != nil {
			t.Fatalf("SubmitURL: %v", err)
		}
	}
	if _, err := p.GetAnalysis(t.Context(), "mock_x"); err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}

	if got := p.SubmitCount(); got != 3 {
		t.Errorf("SubmitCount = %d, want 3 (GetAnalysis must not count)", got)
	}
	if got := len(p.Calls()); got != 4 {
		t.Errorf("len(Calls) = %d, want 4", got)
	}
}

func TestResetClearsCallsButKeepsBehaviour(t *testing.T) {
	t.Parallel()

	p := New()
	if _, err := p.SubmitURL(t.Context(), "https://example.test/x"); err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	p.Reset()
	if got := p.SubmitCount(); got != 0 {
		t.Errorf("SubmitCount after Reset = %d, want 0", got)
	}

	sub, err := p.SubmitURL(t.Context(), "https://example.test/x")
	if err != nil {
		t.Fatalf("SubmitURL after Reset: %v", err)
	}
	if sub.ProviderScanID == "" {
		t.Error("Reset also cleared the configured behaviour")
	}
}

func TestCallsSnapshotIsIndependent(t *testing.T) {
	t.Parallel()

	p := New()
	if _, err := p.SubmitURL(t.Context(), "https://example.test/x"); err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	snapshot := p.Calls()
	snapshot[0] = Call{Method: "tampered"}

	fresh := p.Calls()
	if fresh[0].Method != "SubmitURL" {
		t.Error("Calls() returned a view into internal state, not a copy")
	}
}

// Injected failures must reach the caller unwrapped, so a test can assert on
// the provider error class with errors.Is.
func TestInjectedErrorsArePropagated(t *testing.T) {
	t.Parallel()

	for _, want := range []error{
		providers.ErrAuthFailed,
		providers.ErrRateLimited,
		providers.ErrUnavailable,
		providers.ErrBadResponse,
		providers.ErrNotConfigured,
	} {
		sentinel := want

		p := New(
			WithSubmit(func(context.Context, string) (providers.Submission, error) {
				return providers.Submission{}, sentinel
			}),
		)

		if _, err := p.SubmitURL(t.Context(), "https://example.test/x"); !errors.Is(err, sentinel) {
			t.Errorf("SubmitURL error = %v, want %v", err, sentinel)
		}
	}
}

// Nil options must not blank out the defaults, which would panic on first use.
func TestNilOptionsKeepDefaults(t *testing.T) {
	t.Parallel()

	p := New(WithSubmit(nil), WithAnalysis(nil))

	if _, err := p.SubmitURL(t.Context(), "https://example.test/x"); err != nil {
		t.Fatalf("SubmitURL with nil option: %v", err)
	}
	if _, err := p.GetAnalysis(t.Context(), "mock_x"); err != nil {
		t.Fatalf("GetAnalysis with nil option: %v", err)
	}
}

func TestProviderHonoursContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	p := New()
	if _, err := p.SubmitURL(ctx, "https://example.test/x"); !errors.Is(err, context.Canceled) {
		t.Errorf("SubmitURL error = %v, want context.Canceled", err)
	}
	if _, err := p.GetAnalysis(ctx, "mock_x"); !errors.Is(err, context.Canceled) {
		t.Errorf("GetAnalysis error = %v, want context.Canceled", err)
	}
	if got := p.SubmitCount(); got != 0 {
		t.Errorf("a cancelled call was still recorded: SubmitCount = %d", got)
	}
}

// The fake is shared across goroutines in the concurrency tests, so its
// bookkeeping must be safe. Run under -race to make this meaningful.
func TestProviderIsSafeForConcurrentUse(t *testing.T) {
	t.Parallel()

	p := New()

	const goroutines = 32
	var wg sync.WaitGroup
	wg.Add(goroutines)

	start := time.Now()
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			if _, err := p.SubmitURL(t.Context(), "https://example.test/x"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	if got := p.SubmitCount(); got != goroutines {
		t.Errorf("SubmitCount = %d, want %d", got, goroutines)
	}
	_ = start
}
