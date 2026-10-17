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
//
// SubmissionType is declared because the specification also defines
// `UrlSubmissionStatus`, documented as `SubmissionStatus` plus exactly one
// property, `submission_type`, and named for URL submissions. The 201 response
// of POST /submit/url references the narrower `SubmissionStatus` schema, so
// whether the live service includes the extra property is not documented.
//
// It is declared because the asymmetry of the two failure modes decides it.
// Leaving it out costs nothing when the field is absent, but when the service
// does send it, strict decoding rejects a submission that was accepted upstream:
// the quota is spent, a sandbox job exists, and the job_id — the only handle
// that could recover it — is discarded with the decode error. Declaring a
// documented property of a documented schema avoids that without inventing a
// name; see docs/verified/hybrid-analysis-v2-contract.md.
type submissionStatus struct {
	JobID          string  `json:"job_id"`
	SubmissionID   *string `json:"submission_id"`
	EnvironmentID  *int    `json:"environment_id"`
	SHA256         *string `json:"sha256"`
	SubmissionType *string `json:"submission_type,omitempty"`
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

// sampleSummary is the `SampleSummary` schema: the body of GET /report/{id}/summary.
//
// # Every documented property is declared, not just the consumed ones
//
// The specification defines 55 properties on this schema. Declaring only the
// ten this project reads and decoding with DisallowUnknownFields does not
// "ignore the rest" — it rejects every response that contains any of the other
// 45, so no completed analysis would ever produce a verdict. That failure is
// silent from the outside: it surfaces as a permanently malformed provider
// response, not as a missing field.
//
// So the declared set is the documented set, exactly. That keeps strict
// decoding meaningful in the only way that matters: a property the
// specification does not declare is still rejected, while every property it
// does declare decodes. The boundary is the specification, not this file.
//
// Consumed fields carry their exact documented types. Unconsumed fields are
// json.RawMessage, because a type drift in a field nobody reads must not be
// able to block a verdict — but its presence in the schema still must be, and
// that is enforced by the struct tag.
type sampleSummary struct {
	// Consumed.
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

	// Declared by the specification, not read here.
	AnalysisStartTime             json.RawMessage `json:"analysis_start_time"`
	Certificates                  json.RawMessage `json:"certificates"`
	CertificatesValidationMessage json.RawMessage `json:"certificates_validation_message"`
	ClassificationTags            json.RawMessage `json:"classification_tags"`
	CompromisedHosts              json.RawMessage `json:"compromised_hosts"`
	CrowdStrikeAI                 json.RawMessage `json:"crowdstrike_ai"`
	DetonationParameters          json.RawMessage `json:"detonation_parameters"`
	DLLCharacteristics            json.RawMessage `json:"dll_characteristics"`
	Domains                       json.RawMessage `json:"domains"`
	Entrypoint                    json.RawMessage `json:"entrypoint"`
	EntrypointSection             json.RawMessage `json:"entrypoint_section"`
	EnvironmentDescription        json.RawMessage `json:"environment_description"`
	ExtractedFiles                json.RawMessage `json:"extracted_files"`
	FileMetadata                  json.RawMessage `json:"file_metadata"`
	Hosts                         json.RawMessage `json:"hosts"`
	ImageBase                     json.RawMessage `json:"image_base"`
	ImageFileCharacteristics      json.RawMessage `json:"image_file_characteristics"`
	Imphash                       json.RawMessage `json:"imphash"`
	Interesting                   json.RawMessage `json:"interesting"`
	IsCertificatesValid           json.RawMessage `json:"is_certificates_valid"`
	MachineLearningModels         json.RawMessage `json:"machine_learning_models"`
	MajorOSVersion                json.RawMessage `json:"major_os_version"`
	MD5                           json.RawMessage `json:"md5"`
	MinorOSVersion                json.RawMessage `json:"minor_os_version"`
	MitreAttcks                   json.RawMessage `json:"mitre_attcks"`
	NetworkMode                   json.RawMessage `json:"network_mode"`
	Processes                     json.RawMessage `json:"processes"`
	SHA1                          json.RawMessage `json:"sha1"`
	SHA256                        json.RawMessage `json:"sha256"`
	SHA512                        json.RawMessage `json:"sha512"`
	Signatures                    json.RawMessage `json:"signatures"`
	Size                          json.RawMessage `json:"size"`
	SSDeep                        json.RawMessage `json:"ssdeep"`
	SubmitName                    json.RawMessage `json:"submit_name"`
	Submissions                   json.RawMessage `json:"submissions"`
	Subsystem                     json.RawMessage `json:"subsystem"`
	Tags                          json.RawMessage `json:"tags"`
	TargetURL                     json.RawMessage `json:"target_url"`
	TotalNetworkConnections       json.RawMessage `json:"total_network_connections"`
	TotalProcesses                json.RawMessage `json:"total_processes"`
	TotalSignatures               json.RawMessage `json:"total_signatures"`
	Type                          json.RawMessage `json:"type"`
	TypeShort                     json.RawMessage `json:"type_short"`
	VXFamily                      json.RawMessage `json:"vx_family"`
	Warnings                      json.RawMessage `json:"warnings"`
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
