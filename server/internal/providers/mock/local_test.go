package mock_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/providers/hybridanalysis"
	"cyberguard/server/internal/providers/mock"
)

// The offline provider used for local runs. What matters here is that it is
// deterministic, that every branch can be reached deliberately, and that it
// never touches the network.

func TestLocalIsDeterministic(t *testing.T) {
	t.Parallel()

	const target = "https://example.test/login"

	first, err := mock.Local().SubmitURL(t.Context(), target)
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	// A completely separate provider, as a second process would build.
	second, err := mock.Local().SubmitURL(t.Context(), target)
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	if first.ProviderScanID != second.ProviderScanID {
		t.Errorf("the same URL produced %q then %q; local mode must be deterministic",
			first.ProviderScanID, second.ProviderScanID)
	}
}

// Every documented keyword reaches the verdict it advertises.
func TestLocalKeywordRules(t *testing.T) {
	t.Parallel()

	cases := []struct {
		target        string
		wantVerdict   string
		wantFinished  bool
		wantState     string
		wantErrorType string
	}{
		{target: "https://example.test/malicious/phish", wantVerdict: "malicious", wantFinished: true, wantState: "SUCCESS"},
		{target: "https://example.test/suspicious/thing", wantVerdict: "suspicious", wantFinished: true, wantState: "SUCCESS"},
		{target: "https://example.test/no-threat", wantVerdict: "no specific threat", wantFinished: true, wantState: "SUCCESS"},
		{target: "https://example.test/clean", wantVerdict: "no specific threat", wantFinished: true, wantState: "SUCCESS"},
		{target: "https://example.test/some/ordinary/page", wantVerdict: "no specific threat", wantFinished: true, wantState: "SUCCESS"},
		{target: "https://example.test/error/boom", wantVerdict: "", wantFinished: true, wantState: "ERROR", wantErrorType: "MOCK_ANALYSIS_FAILED"},
	}

	for _, tc := range cases {
		t.Run(tc.target, func(t *testing.T) {
			t.Parallel()

			p := mock.Local()
			sub, err := p.SubmitURL(t.Context(), tc.target)
			if err != nil {
				t.Fatalf("SubmitURL: %v", err)
			}

			// Poll past the deliberate in-progress polls.
			var last providers.Analysis
			for range 10 {
				last, err = p.GetAnalysis(t.Context(), sub.ProviderScanID)
				if err != nil {
					t.Fatalf("GetAnalysis: %v", err)
				}
				if last.Finished {
					break
				}
			}

			if !last.Finished {
				t.Fatal("the analysis never reached a terminal state")
			}
			if last.Classification != tc.wantVerdict {
				t.Errorf("classification = %q, want %q", last.Classification, tc.wantVerdict)
			}
			if last.ProviderState != tc.wantState {
				t.Errorf("provider state = %q, want %q", last.ProviderState, tc.wantState)
			}
			if tc.wantErrorType != "" && last.ErrorType != tc.wantErrorType {
				t.Errorf("error type = %q, want %q", last.ErrorType, tc.wantErrorType)
			}
		})
	}
}

// The first polls must report "still running", so a local run exercises the
// real polling loop rather than getting a finished answer immediately.
func TestLocalReportsProgressBeforeFinishing(t *testing.T) {
	t.Parallel()

	p := mock.Local()
	sub, err := p.SubmitURL(t.Context(), "https://example.test/ordinary")
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	first, err := p.GetAnalysis(t.Context(), sub.ProviderScanID)
	if err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}
	if first.Finished {
		t.Error("the first poll already reported a finished analysis; polling is never exercised")
	}
	if first.ProviderState != "IN_PROGRESS" {
		t.Errorf("provider state = %q, want IN_PROGRESS", first.ProviderState)
	}

	// Exactly pollsBeforeTerminal more polls, then it must be terminal.
	for range 5 {
		last, err := p.GetAnalysis(t.Context(), sub.ProviderScanID)
		if err != nil {
			t.Fatalf("GetAnalysis: %v", err)
		}
		if last.Finished {
			if last.ProviderState != "SUCCESS" {
				t.Errorf("final provider state = %q, want SUCCESS", last.ProviderState)
			}
			return
		}
	}
	t.Error("the analysis never finished, however many times it was polled")
}

// "/slow" never terminates, so the timed_out and recovery paths can be seen
// deliberately rather than waited for.
func TestLocalSlowURLNeverFinishes(t *testing.T) {
	t.Parallel()

	p := mock.Local()
	sub, err := p.SubmitURL(t.Context(), "https://example.test/slow/forever")
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	for range 25 {
		a, err := p.GetAnalysis(t.Context(), sub.ProviderScanID)
		if err != nil {
			t.Fatalf("GetAnalysis: %v", err)
		}
		if a.Finished {
			t.Fatal("a /slow URL reported a finished analysis")
		}
	}
}

// An unknown job id must be refused rather than answered with a guess. A
// fabricated verdict is the one thing this project must never produce.
func TestLocalRefusesAnUnknownJob(t *testing.T) {
	t.Parallel()

	if _, err := mock.Local().GetAnalysis(t.Context(), "mock_never_submitted"); err == nil {
		t.Error("GetAnalysis answered for a job that was never submitted")
	}
}

// The provider must identify itself honestly, or stored documents would claim a
// real sandbox produced the verdict.
func TestLocalNeverClaimsToBeHybridAnalysis(t *testing.T) {
	t.Parallel()

	if got := mock.Local().Name(); got == hybridanalysis.ProviderName {
		t.Errorf("Name() = %q; local mode must not claim the real provider", got)
	}
	if got := mock.Local().Name(); got != mock.LocalProviderName {
		t.Errorf("Name() = %q, want %q", got, mock.LocalProviderName)
	}
}

// A typed nil must not panic: it satisfies the interface and reports a name.
func TestNilProviderIsSafe(t *testing.T) {
	t.Parallel()

	var p *mock.Provider
	if got := p.Name(); got == "" {
		t.Error("a nil provider reported an empty name")
	}
}

// Concurrent use must be safe: several worker goroutines share one provider.
func TestLocalIsConcurrencySafe(t *testing.T) {
	t.Parallel()

	p := mock.Local()
	const n = 40

	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			target := "https://example.test/malicious/" + string(rune('a'+i%20))
			sub, err := p.SubmitURL(context.Background(), target)
			if err != nil {
				t.Errorf("SubmitURL: %v", err)
				return
			}
			if _, err := p.GetAnalysis(context.Background(), sub.ProviderScanID); err != nil {
				t.Errorf("GetAnalysis: %v", err)
			}
		}()
	}
	wg.Wait()

	if p.SubmitCount() != n {
		t.Errorf("SubmitCount = %d, want %d", p.SubmitCount(), n)
	}
}

// Classification must survive the real normalisation path, so a local run
// produces the same verdict vocabulary a production run would.
func TestLocalClassificationsMapToKnownVerdicts(t *testing.T) {
	t.Parallel()

	for _, classification := range []string{"malicious", "suspicious", "no specific threat"} {
		a := providers.Analysis{Finished: true, Classification: classification, ProviderState: "SUCCESS"}
		got := hybridanalysis.NormaliseVerdict(a)
		if !got.Valid() {
			t.Errorf("NormaliseVerdict(%q) = %q, which is not in the vocabulary", classification, got)
		}
	}
}

// A submitted URL must not appear in anything the provider hands back; the
// caller supplies it and keeps it.
func TestLocalNeverEchoesTheURLInAnalysis(t *testing.T) {
	t.Parallel()

	const target = "https://secret.example.test/pay?token=abc123"
	p := mock.Local()
	sub, err := p.SubmitURL(t.Context(), target)
	if err != nil {
		t.Fatalf("SubmitURL: %v", err)
	}

	a, err := p.GetAnalysis(t.Context(), sub.ProviderScanID)
	if err != nil {
		t.Fatalf("GetAnalysis: %v", err)
	}
	for _, field := range []string{a.Classification, a.ProviderState, a.ErrorType, a.ErrorOrigin} {
		for _, leak := range []string{"secret.example.test", "abc123", "/pay"} {
			if strings.Contains(field, leak) {
				t.Errorf("analysis field %q leaked %q", field, leak)
			}
		}
	}
}

// Timing must not influence the outcome.
func TestLocalIgnoresWallClock(t *testing.T) {
	t.Parallel()

	a := providers.Analysis{
		Finished:       true,
		Classification: "malicious",
		ProviderState:  "SUCCESS",
		ReportedAt:     time.Time{},
	}
	if got := hybridanalysis.NormaliseVerdict(a); string(got) != "malicious" {
		t.Errorf("verdict = %q, want malicious", got)
	}
}
