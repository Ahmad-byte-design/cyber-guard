package mock

import (
	"context"
	"strings"
	"time"

	"cyberguard/server/internal/providers"
)

// Local mode: a deterministic, offline stand-in for a real analysis provider.
//
// # What this is for
//
// Running the whole system — HTTP API, MongoDB, in-process scan runner, verdict —
// on a machine with no provider account, and with an absolute guarantee that no
// request leaves the process.
//
// That guarantee is the point. A development setup that silently falls back to a
// real provider when a key is missing would spend real quota and, more
// importantly, would make "did my pipeline work?" unanswerable: every test run
// would differ because the upstream service had different state.
//
// # Determinism
//
// The outcome is a pure function of the submitted URL: the same URL always
// produces the same verdict, in this process and in the next. Nothing is
// randomised, time-dependent or load-dependent, so a workflow test is
// reproducible and a demo does not surprise anyone.
//
// The rules are keyword-based so every branch can be exercised deliberately:
//
//	/malicious          -> malicious
//	/suspicious         -> suspicious
//	/no-threat or /clean -> no_threat_detected
//	/error              -> the provider reports a failed analysis
//	/slow               -> the report stays unfinished, so polling is exercised
//	anything else       -> no_threat_detected
//
// # The default is deliberately not "malicious"
//
// Defaulting to a threat would make every casual demo look alarming and would
// train the reader to ignore the verdict. Defaulting to a clean result makes
// the interesting cases opt-in and explicit.

// LocalProviderName is what Local() records on documents.
const LocalProviderName = "mock"

// pollsBeforeTerminal is how many polls return "still running" before the
// terminal report.
//
// Two polls means a worker configured with a short poll interval really does
// exercise the poll loop and the state recording, rather than getting a
// finished answer on the first request. One poll would make the polling code
// untested in local use; three would make every manual demo feel slow.
const pollsBeforeTerminal = 2

// Local returns a Provider that analyses URLs offline and deterministically.
//
// It is safe for concurrent use.
func Local() *Provider {
	p := &Provider{
		name:     LocalProviderName,
		polls:    make(map[string]int),
		outcomes: make(map[string]localOutcome),
	}

	p.submit = func(_ context.Context, rawURL string) (providers.Submission, error) {
		id := scanIDFor(rawURL)

		p.mu.Lock()
		p.outcomes[id] = outcomeFor(rawURL)
		p.polls[id] = 0
		p.mu.Unlock()

		return providers.Submission{
			ProviderScanID: id,
			// A deterministic environment id keeps documents well-formed
			// without implying a real sandbox exists.
			EnvironmentID: intPtr(0),
			State:         providers.StateQueued,
		}, nil
	}

	p.analysis = func(_ context.Context, providerScanID string) (providers.Analysis, error) {
		p.mu.Lock()
		outcome, known := p.outcomes[providerScanID]
		polls := p.polls[providerScanID]
		p.polls[providerScanID] = polls + 1
		p.mu.Unlock()

		if !known {
			// The same answer a real provider gives for an unknown job: the
			// caller made a mistake, and guessing would be worse than saying so.
			return providers.Analysis{}, providers.ErrBadResponse
		}

		now := time.Now().UTC()

		if outcome.failed {
			return providers.Analysis{
				Finished:      true,
				ProviderState: "ERROR",
				// A stable, non-prose token. Nothing here is a real provider
				// diagnostic and nothing here is shown to a client.
				ErrorType:   "MOCK_ANALYSIS_FAILED",
				ErrorOrigin: "mock",
				ReportedAt:  now,
			}, nil
		}

		if polls < outcome.slowPolls {
			return providers.Analysis{
				Finished:      false,
				ProviderState: "IN_PROGRESS",
				ReportedAt:    now,
			}, nil
		}

		return providers.Analysis{
			Finished:       true,
			ProviderState:  "SUCCESS",
			Classification: outcome.classification,
			ReportedAt:     now,
		}, nil
	}

	return p
}

// localOutcome is the precomputed result for one URL.
type localOutcome struct {
	classification string
	failed         bool
	slowPolls      int
}

// outcomeFor maps a URL onto its deterministic outcome.
//
// The keywords are matched against the whole URL, lower-cased, so
// "https://example.test/malicious/phish" and
// "HTTPS://EXAMPLE.TEST/MALICIOUS/phish" both behave the same.
func outcomeFor(rawURL string) localOutcome {
	u := strings.ToLower(rawURL)

	switch {
	case strings.Contains(u, "/error"):
		return localOutcome{failed: true}

	case strings.Contains(u, "/slow"):
		// Never terminal within a normal poll budget, so the timed_out path
		// and the recovery path can both be observed deliberately.
		return localOutcome{slowPolls: 1 << 20}

	case strings.Contains(u, "/malicious"):
		return localOutcome{classification: "malicious"}

	case strings.Contains(u, "/suspicious"):
		return localOutcome{classification: "suspicious"}

	case strings.Contains(u, "/no-threat"), strings.Contains(u, "/clean"):
		return localOutcome{classification: "no specific threat"}

	default:
		return localOutcome{classification: "no specific threat", slowPolls: pollsBeforeTerminal}
	}
}

// Name reports the provider identifier recorded on documents.
//
// It satisfies providers.AnalysisProvider. A Provider built with New — i.e. a
// test double — and one built with Local both report "mock", so a document
// never claims a real provider produced the verdict.
func (p *Provider) Name() string {
	// Nil-safe on purpose. A typed nil stored in the AnalysisProvider
	// interface is a non-nil interface holding a nil pointer, so any caller
	// that checks "is the provider nil?" in the interface sense would be
	// wrong. Returning a name here keeps that mistake harmless.
	if p == nil {
		return "mock"
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if p.name == "" {
		return "mock"
	}
	return p.name
}

// Quota reports a synthetic quota state.
//
// It exists so local mode can answer "is there quota?" without contacting
// anything. It always reports quota remaining: a local run that started failing
// with "quota exhausted" would be confusing, and a real quota could not be
// consulted anyway.
func (p *Provider) Quota() (detonationReached, quickScanReached bool) {
	return false, false
}

func intPtr(v int) *int { return &v }
