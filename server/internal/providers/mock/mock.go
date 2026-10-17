// Package mock provides a deterministic in-memory AnalysisProvider for tests.
//
// It exists so that no automated test needs to reach a real analysis provider.
// docs/architecture/CYBERGUARD_PROJECT.md §14 and ADR 0010 both require it: a
// live submission spends real quota, depends on the network, and may breach the
// provider's terms for automated submission.
//
// Design:
//
//   - Behaviour is injected as function fields, so a test states exactly what
//     the provider does in the scenario under test.
//   - Calls are recorded so tests can assert that a submission happened once,
//     or not at all.
//   - It depends on nothing outside the standard library and providers, so it is
//     usable from any package's tests.
//
// It never logs or stores raw URLs. Recorded calls hold the URL only for the
// lifetime of the test, and Call is documented as test-only data.
package mock

import (
	"context"
	"sync"
	"time"

	"cyberguard/server/internal/providers"
)

// Compile-time proof that the mock satisfies the contract.
var _ providers.AnalysisProvider = (*Provider)(nil)

// SubmitFunc is the injected behaviour of SubmitURL.
type SubmitFunc func(ctx context.Context, rawURL string) (providers.Submission, error)

// AnalysisFunc is the injected behaviour of GetAnalysis.
type AnalysisFunc func(ctx context.Context, providerScanID string) (providers.Analysis, error)

// Call records one interaction with the provider.
//
// RawURL is present so tests can assert what was submitted. It is deliberately
// not redacted: a test asserting "the correct URL reached the provider" is
// legitimate, and this type never escapes the test process.
type Call struct {
	Method         string
	RawURL         string
	ProviderScanID string
}

// Provider is a configurable AnalysisProvider.
//
// The zero value is not usable; construct with New. A Provider is safe for
// concurrent use.
type Provider struct {
	mu    sync.Mutex
	calls []Call

	submit   SubmitFunc
	analysis AnalysisFunc

	// name is the provider identifier recorded on documents. Local() sets it;
	// New() leaves it empty and Name() falls back to "mock".
	name string

	// polls and outcomes back Local(). They are unused by New(), which is
	// fine: a test-injected provider answers from its own closures.
	polls    map[string]int
	outcomes map[string]localOutcome
}

// New returns a Provider whose SubmitURL succeeds with scanID and whose
// GetAnalysis returns a terminal, unclassified report.
//
// Override either behaviour with the With* options.
func New(opts ...Option) *Provider {
	p := &Provider{
		submit: func(_ context.Context, rawURL string) (providers.Submission, error) {
			return providers.Submission{
				ProviderScanID: scanIDFor(rawURL),
				State:          providers.StateQueued,
			}, nil
		},
		analysis: func(_ context.Context, id string) (providers.Analysis, error) {
			return providers.Analysis{
				Finished:       true,
				Classification: "",
				ReportedAt:     time.Time{},
			}, nil
		},
	}
	for _, opt := range opts {
		opt(p)
	}
	return p
}

// Option customises a Provider.
type Option func(*Provider)

// WithSubmit replaces the SubmitURL behaviour.
func WithSubmit(fn SubmitFunc) Option {
	return func(p *Provider) {
		if fn != nil {
			p.submit = fn
		}
	}
}

// WithAnalysis replaces the GetAnalysis behaviour.
func WithAnalysis(fn AnalysisFunc) Option {
	return func(p *Provider) {
		if fn != nil {
			p.analysis = fn
		}
	}
}

// SubmitURL implements providers.AnalysisProvider.
func (p *Provider) SubmitURL(ctx context.Context, rawURL string) (providers.Submission, error) {
	if err := ctx.Err(); err != nil {
		return providers.Submission{}, err
	}

	p.mu.Lock()
	p.calls = append(p.calls, Call{Method: "SubmitURL", RawURL: rawURL})
	p.mu.Unlock()

	return p.submit(ctx, rawURL)
}

// GetAnalysis implements providers.AnalysisProvider.
func (p *Provider) GetAnalysis(ctx context.Context, providerScanID string) (providers.Analysis, error) {
	if err := ctx.Err(); err != nil {
		return providers.Analysis{}, err
	}

	p.mu.Lock()
	p.calls = append(p.calls, Call{Method: "GetAnalysis", ProviderScanID: providerScanID})
	p.mu.Unlock()

	return p.analysis(ctx, providerScanID)
}

// Calls returns a copy of the recorded interactions, in order.
func (p *Provider) Calls() []Call {
	p.mu.Lock()
	defer p.mu.Unlock()

	out := make([]Call, len(p.calls))
	copy(out, p.calls)
	return out
}

// SubmitCount returns how many times SubmitURL was called. This is the
// assertion behind the "one fingerprint, one provider submission" guarantee.
func (p *Provider) SubmitCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()

	n := 0
	for _, c := range p.calls {
		if c.Method == "SubmitURL" {
			n++
		}
	}
	return n
}

// Reset clears recorded calls. Behaviour is left intact.
func (p *Provider) Reset() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.calls = nil
}

// scanIDFor derives a stable, opaque identifier from a URL.
//
// It is a plain hash rather than an HMAC on purpose: this is test scaffolding,
// and the real fingerprint key must never reach a test fixture. Nothing here
// is persisted.
func scanIDFor(rawURL string) string {
	const hexDigits = "0123456789abcdef"

	// FNV-1a, inline, so the mock stays dependency-free.
	const (
		offset64 = 14695981039346656037
		prime64  = 1099511628211
	)
	h := uint64(offset64)
	for i := 0; i < len(rawURL); i++ {
		h ^= uint64(rawURL[i])
		h *= prime64
	}

	out := make([]byte, 16)
	for i := range out {
		out[i] = hexDigits[(h>>(4*i))&0xf]
	}
	return "mock_" + string(out)
}
