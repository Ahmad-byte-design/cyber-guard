// Package providers defines the contract every external analysis provider must
// satisfy, plus the provider-agnostic types that cross that boundary.
//
// Why this exists: the rest of the application must not depend on any provider's
// wire format. A provider adapter owns authentication, HTTP, wire types, retry
// classification, polling and error mapping; it hands back only these types.
//
// Deliberately absent: anything resembling a specific provider's endpoints,
// statuses or classifications. The Hybrid Analysis contract is unverified — see
// docs/hybrid-analysis-integration.md §2 and §9 — so encoding guesses here
// would produce an adapter that compiles and fails against the live API.
//
// # Placement of AnalysisProvider
//
// The consumer-side rule says the interface belongs in the package that consumes
// it, which will be internal/scans. That package belongs to the scan lifecycle,
// which is explicitly out of scope for this phase. Until it exists, the contract
// lives here so the mock has something real to implement.
//
// TODO: move AnalysisProvider and these types into internal/scans when the
// scan lifecycle is built, and leave this package holding only adapters. The
// mock moves with them.
package providers

import (
	"context"
	"errors"
	"strings"
	"time"
)

// AnalysisProvider is the behaviour the scan lifecycle requires from any
// external analysis provider.
//
// Callers pass a context with a deadline; implementations must honour it and
// must not impose a longer timeout of their own.
type AnalysisProvider interface {
	// SubmitURL asks the provider to analyse rawURL.
	//
	// rawURL is plaintext because the provider requires it in plaintext. This
	// is the only point in the system where a raw URL crosses a process or
	// network boundary, so it is the point where privacy obligations concentrate.
	SubmitURL(ctx context.Context, rawURL string) (Submission, error)
	// GetAnalysis retrieves the provider's current report for a submission.
	GetAnalysis(ctx context.Context, providerScanID string) (Analysis, error)

	// Name is the identifier recorded on scan and assessment documents.
	//
	// It is part of the contract rather than a constant somewhere else
	// because the system can run against more than one provider. A record
	// that claims "hybrid-analysis" when a mock produced the verdict is not
	// merely untidy: an operator reading the audit trail would draw the
	// wrong conclusion about where a verdict came from.
	Name() string
}

// State is the provider-agnostic progress of a submission.
type State string

const (
	// StateQueued means the provider accepted the submission and has not begun.
	StateQueued State = "queued"
	// StateRunning means analysis is in progress.
	StateRunning State = "running"
	// StateTerminal means the provider considers the analysis finished.
	//
	// "Terminal" says nothing about the outcome. A finished analysis may still
	// be inconclusive, and a finished analysis that failed must not be
	// interpreted as clean.
	StateTerminal State = "terminal"
)

// Valid reports whether s is one of the defined states.
func (s State) Valid() bool {
	switch s {
	case StateQueued, StateRunning, StateTerminal:
		return true
	default:
		return false
	}
}

// Submission is the outcome of asking a provider to analyse a URL.
type Submission struct {
	// ProviderScanID is the provider's opaque handle for later retrieval.
	//
	// It is the only field a caller cannot proceed without: without it there
	// is nothing to poll, and a submission with no handle cannot be resumed
	// after a restart.
	ProviderScanID string

	// ProviderSubmissionID is the provider's own identifier for the submission
	// event, as distinct from the analysis job.
	//
	// The verified Hybrid Analysis 201 response declares it nullable, so an
	// empty value is a real outcome and not a decoding failure. It is carried
	// through only so the scan record can retain it for diagnosis; nothing
	// polls with it.
	ProviderSubmissionID string

	// EnvironmentID is the sandbox the provider ran the analysis in. Nil when
	// the provider did not report one.
	EnvironmentID *int

	// State is the provider's reported progress.
	State State
}

// Analysis is a provider report that has not yet been interpreted.
type Analysis struct {
	// Finished reports whether the provider considers the analysis complete.
	Finished bool
	// Classification is the provider's own label, passed through verbatim.
	//
	// It is deliberately a string. The mapping from provider vocabulary to
	// CyberGuard verdicts belongs to internal/verdicts, and that mapping is
	// unverified. Encoding a verdict here would both duplicate that logic and
	// risk inventing provider behaviour.
	Classification string
	// ProviderState is the provider's raw state token, passed through
	// verbatim.
	//
	// It exists because a completed analysis can have *failed*: a provider
	// distinguishes "processed successfully" from "processed and errored".
	// Collapsing that into Finished alone would make a failed analysis
	// indistinguishable from a clean one, which is exactly the mistake
	// ADR 0011 exists to prevent.
	ProviderState string
	// ErrorType and ErrorOrigin carry provider-side failure diagnostics.
	//
	// Adapters must populate these with provider-defined codes, never raw
	// provider prose, so nothing can leak into a client-visible response.
	ErrorType   string
	ErrorOrigin string
	// Raw is the bounded provider payload, passed to the normalisation layer.
	//
	// Never persisted — see docs/data-model.md §7.
	Raw []byte
	// ReportedAt is when the provider produced this report.
	ReportedAt time.Time
}

// Provider state tokens that mean the analysis errored.
//
// These are compared case-insensitively, because a provider is free to change
// casing and a verdict must not depend on it.
const (
	stateError          = "ERROR"
	statePartialSuccess = "PARTIAL_SUCCESS"
)

// Failed reports whether the provider states the analysis errored.
//
// Deliberately separate from Finished: an analysis can be finished *and* have
// failed. Treating that as a clean result is the single most dangerous mistake
// available in this pipeline.
func (a Analysis) Failed() bool {
	switch strings.ToUpper(strings.TrimSpace(a.ProviderState)) {
	case stateError, statePartialSuccess:
		return true
	default:
		return false
	}
}

// Provider error classes. These are stable, provider-agnostic categories that
// callers branch on; they never carry upstream text.
//
// They exist because retry policy depends on the class, not on the message. A
// 401 must not be retried; a 429 must honour Retry-After; a 5xx should be
// retried. Mapping those into three named categories is what keeps the retry
// loop out of the transport layer.
var (
	// ErrAuthFailed is a permanent authentication or authorisation failure.
	// Retrying it wastes quota and may lock the credential.
	ErrAuthFailed = errors.New("providers: authentication failed")
	// ErrRateLimited is a quota or rate-limit rejection. Honour Retry-After.
	ErrRateLimited = errors.New("providers: rate limited")
	// ErrUnavailable is a transient failure: network error, timeout, 5xx.
	ErrUnavailable = errors.New("providers: temporarily unavailable")
	// ErrBadResponse is a malformed, oversized or unrecognised response.
	ErrBadResponse = errors.New("providers: malformed provider response")
	// ErrNotConfigured means the provider has no usable credentials.
	//
	// Distinct from ErrAuthFailed so readiness can report "not configured"
	// separately from "configured but rejected".
	ErrNotConfigured = errors.New("providers: not configured")
)
