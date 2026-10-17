package hybridanalysis

import "encoding/json"

// Wire types transcribed from the official Hybrid Analysis API v2
// specification (OpenAPI 3.0.0, docs version 2.38.0), retrieved 2026-10-16 from
// https://hybrid-analysis.com/bff/api-docs/v2
//
// The distilled contract, with citations, is in
// docs/verified/hybrid-analysis-v2-contract.md. Every field below was read from
// the specification; none is inferred.
//
// The specification marks many response fields nullable, so every field that the
// provider may omit is a pointer. Decoding an absent value into a plain int or
// string silently produces a zero that looks like a real answer — for a
// `threat_level` of 0 that would mean "no threat" when it means "not reported".

// submissionStatus is the `SubmissionStatus` schema: the body of a 201 response
// to POST /submit/url.
type submissionStatus struct {
	JobID         string  `json:"job_id"`
	SubmissionID  *string `json:"submission_id"`
	EnvironmentID *int    `json:"environment_id"`
	SHA256        *string `json:"sha256"`
}

// sampleState is the `SampleState` schema: the body of GET /report/{id}/state.
type sampleState struct {
	State          *string         `json:"state"`
	ErrorType      *string         `json:"error_type"`
	ErrorOrigin    *string         `json:"error_origin"`
	Error          *string         `json:"error"`
	RelatedReports []sampleVerdict `json:"related_reports"`
}

// sampleVerdict is the `SampleVerdict` schema, returned inside related_reports.
type sampleVerdict struct {
	JobID         *string `json:"job_id"`
	EnvironmentID *int    `json:"environment_id"`
	State         *string `json:"state"`
	ErrorType     *string `json:"error_type"`
	ErrorOrigin   *string `json:"error_origin"`
	SHA256        *string `json:"sha256"`
	Verdict       *string `json:"verdict"`
}

// sampleSummary is the `SampleSummary` schema. Only the fields this project
// consumes are declared; the specification defines many more, and decoding
// ignores the rest rather than failing on them.
type sampleSummary struct {
	JobID         *string `json:"job_id"`
	EnvironmentID *int    `json:"environment_id"`
	State         *string `json:"state"`
	Verdict       *string `json:"verdict"`
	ThreatLevel   *int    `json:"threat_level"`
	AVDetect      *int    `json:"av_detect"`
	ThreatScore   *int    `json:"threat_score"`
	ErrorType     *string `json:"error_type"`
	ErrorOrigin   *string `json:"error_origin"`
	URLAnalysis   *bool   `json:"url_analysis"`
}

// apiError is the `Error` schema: the body of a failed response.
//
// The specification defines only a single `message` string. That message is
// provider prose and must never reach a log at Info level or a client response;
// this package extracts it for Debug-level logging only.
type apiError struct {
	Message string `json:"message"`
}

// submissionQuota is the `SubmissionQuota` schema: GET /key/submission-quota.
//
// Only quota_reached is read. QuotaForType carries quota/used/available objects
// whose inner shape is not needed here; see quotaOverall for why they are
// declared as raw JSON rather than typed.
type submissionQuota struct {
	Detonation *quotaOverall `json:"detonation"`
	QuickScan  *quotaOverall `json:"quick_scan"`
}

// quotaOverall is the `QuotaOverall` schema.
//
// Every member the specification declares is modelled, including `total`.
//
// `total` is marked deprecated in the specification but the live service still
// returns it, and this package decodes with DisallowUnknownFields. Leaving it
// undeclared therefore did not merely ignore a field — it made every quota
// probe fail with `json: unknown field "total"`. A deprecated field that is
// still sent is part of the contract, so it is declared and simply unread.
//
// `apikey` and `total` are both QuotaForType objects (quota/used/available,
// each nullable). They are modelled as json.RawMessage because nothing here
// reads them: declaring a shape for a field never used is how invented field
// names get into a codebase. Verified against the v2 OpenAPI document.
type quotaOverall struct {
	Total        json.RawMessage `json:"total"`
	APIVKey      json.RawMessage `json:"apikey"`
	QuotaReached *bool           `json:"quota_reached"`
}

// Documented Hybrid Analysis state tokens.
//
// The specification documents these in the SampleState.state description:
// a child is processed when its state is SUCCESS or ERROR, and a container
// whose children finished with mixed states is PARTIAL_SUCCESS.
const (
	providerStateInQueue        = "IN_QUEUE"
	providerStateInProgress     = "IN_PROGRESS"
	providerStateSuccess        = "SUCCESS"
	providerStateError          = "ERROR"
	providerStatePartialSuccess = "PARTIAL_SUCCESS"
)

// Documented environment IDs. Used only to name the default in configuration
// and in log output; the specification does not recommend one.
const (
	envWindows11x64  = 140
	envWindows10x64  = 160
	envLinuxUbuntu24 = 330
	envMacOSArm64    = 430
)

// EnvironmentName returns a human-readable name for a documented environment ID,
// or "unknown" for an ID the specification does not list.
//
// It exists so a submission log identifies the sandbox without an operator
// needing to memorise the table.
func EnvironmentName(id int) string {
	switch id {
	case envWindows11x64:
		return "Windows 11 64 bit"
	case envWindows10x64:
		return "Windows 10 64 bit"
	case envLinuxUbuntu24:
		return "Linux (Ubuntu 24.04, 64 bit)"
	case envMacOSArm64:
		return "macOS Tahoe (ARM64)"
	case 200:
		return "Android Static Analysis"
	case 120:
		return "Windows 7 64 bit"
	case 110:
		return "Windows 7 32 bit (HWP support)"
	case 100:
		return "Windows 7 32 bit"
	default:
		return "unknown"
	}
}

// deref returns the value behind p, or the zero value when p is nil. The
// specification marks most response fields nullable, so this is the common case
// rather than the exceptional one.
func deref[T any](p *T) T {
	if p == nil {
		var zero T
		return zero
	}
	return *p
}
