// Package models defines the shapes that cross the API boundary and are
// persisted in MongoDB: the submission document, the published ruleset
// snapshot and its version state.
//
// Provider-specific field names stop in the hybridanalysis package. Everything
// an API client or the database sees is named here, once.
package models

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

// ProviderName is recorded on every submission, so a document always tells the
// truth about where its data came from.
const ProviderName = "hybrid-analysis"

// Submission status values.
//
// "pending" means the provider accepted the analysis but has not reported
// `finished: true` yet. "completed" means the provider reported a finished
// scan and this service normalized it. A record is only ever marked completed
// from a provider response that carried `finished: true`.
const (
	StatusPending   = "pending"
	StatusCompleted = "completed"

	// LegacyStatusSubmitted is the status older records were written with
	// before result retrieval existed. Records still carrying it are
	// treated exactly like StatusPending — see Submission.IsPending.
	LegacyStatusSubmitted = "submitted"
)

// Application verdict vocabulary. Verdicts are never guessed: a verdict is
// only set once the provider reported `finished: true` and the scanner
// evidence could be mapped by the documented normalization policy
// (internal/services/verdict.go). Until then Verdict is JSON null.
const (
	VerdictMalicious    = "malicious"
	VerdictSuspicious   = "suspicious"
	VerdictNoThreat     = "no_threat_detected"
	VerdictInconclusive = "inconclusive"
	VerdictUnknown      = "unknown"
)

// Verdicts is the allowed verdict vocabulary, in documentation order. It is
// used by tests and documentation examples.
var Verdicts = []string{
	VerdictMalicious,
	VerdictSuspicious,
	VerdictNoThreat,
	VerdictInconclusive,
	VerdictUnknown,
}

// SubmissionCollection is the only collection this service creates.
const SubmissionCollection = "url_submissions"

// Submission is one check-url request and the provider data returned for it.
//
// The same struct is the MongoDB document and the JSON response item, so what
// is documented, what is stored and what is served cannot drift apart.
type Submission struct {
	// ID is the internal document ID.
	ID bson.ObjectID `bson:"_id,omitempty" json:"id"`

	// URL is the canonicalized URL. Lookup and storage use the same
	// canonicalization, so cache hits are deterministic.
	URL string `bson:"url" json:"url"`

	// URLHash is the hex SHA-256 digest of URL. It is the cache key this
	// service looks up before contacting the provider and backs the unique
	// index that keeps one record per canonical URL. Internal only: never
	// serialized to API clients.
	URLHash string `bson:"urlHash,omitempty" json:"-"`

	// Provider is the analysis provider that produced the data.
	Provider string `bson:"provider" json:"provider"`

	// ProviderID is the identifier the provider returned, when it returned
	// one. Never fabricated. Pending records reuse it instead of creating
	// another submission for the same URL.
	ProviderID string `bson:"providerId,omitempty" json:"providerId,omitempty"`

	// SHA256 is the provider-reported sample digest, when reported.
	SHA256 string `bson:"sha256,omitempty" json:"sha256,omitempty"`

	// ScanType is the documented `scan_type` value the submission used.
	ScanType string `bson:"scanType" json:"scanType"`

	// Status is the app-level state: "pending" or "completed". It is
	// derived only from the provider's own `finished` flag, never guessed.
	Status string `bson:"status" json:"status"`

	// Finished is the provider's own completion flag, passed through.
	Finished bool `bson:"finished" json:"finished"`

	// Scanners carries the per-scanner data from the provider's deprecated
	// `scanners` array, when the provider still sends one.
	Scanners []Scanner `bson:"scanners,omitempty" json:"scanners,omitempty"`

	// ScannersV2 is the provider's `scanners_v2` object passed through
	// verbatim. Its keys are the provider's, not this API's, and are
	// documented as passthrough. Nil when the provider sent none.
	ScannersV2 bson.M `bson:"scannersV2,omitempty" json:"scannersV2,omitempty"`

	// Reports lists provider report references, when returned.
	Reports []string `bson:"reports,omitempty" json:"reports,omitempty"`

	// Verdict is nil unless the provider reported a finished scan and the
	// documented normalization policy could map its scanner evidence onto
	// the verdict vocabulary. Provider errors and missing scanner data are
	// never read as a safe result.
	Verdict *string `bson:"verdict" json:"verdict"`

	// CreatedAt and UpdatedAt are always UTC.
	CreatedAt time.Time `bson:"createdAt" json:"createdAt"`
	UpdatedAt time.Time `bson:"updatedAt" json:"updatedAt"`

	// Rule is the declarativeNetRequest rule a browser extension can
	// install for this URL immediately, derived from the stored URL and
	// verdict with the same mapping as the published ruleset. It is set
	// only on API responses for assessments carrying a published verdict
	// (malicious or suspicious), and it is never persisted.
	Rule *DNRRule `bson:"-" json:"rule,omitempty"`
}

// IsCompleted reports whether the record holds a provider-confirmed finished
// result. Only such records may be served as cached final results.
func (s *Submission) IsCompleted() bool {
	return s.Status == StatusCompleted
}

// IsPending reports whether the record is waiting on the provider. Records
// written by older versions with LegacyStatusSubmitted count as pending.
func (s *Submission) IsPending() bool {
	return s.Status == StatusPending || s.Status == LegacyStatusSubmitted
}

// Scanner is one scanner entry, in the provider's documented shape
// (`Scanner` schema of the official v2 specification). Fields the provider may
// omit are pointers so "not reported" can never read as a zero value.
type Scanner struct {
	Name         string  `json:"name" bson:"name"`
	Status       string  `json:"status" bson:"status"`
	StatusRaw    string  `json:"statusRaw" bson:"statusRaw"`
	ErrorMessage *string `json:"errorMessage,omitempty" bson:"errorMessage,omitempty"`
	Progress     int     `json:"progress" bson:"progress"`
	Total        *int    `json:"total,omitempty" bson:"total,omitempty"`
	Positives    *int    `json:"positives,omitempty" bson:"positives,omitempty"`
	Percent      *int    `json:"percent,omitempty" bson:"percent,omitempty"`

	// AntiVirusResults is populated by the provider only for accounts with
	// default privileges or higher; absent otherwise.
	AntiVirusResults []AntiVirusResult `json:"antiVirusResults,omitempty" bson:"antiVirusResults,omitempty"`
}

// AntiVirusResult is one engine verdict inside a scanner entry, in the
// provider's documented shape.
type AntiVirusResult struct {
	Name        string `json:"name" bson:"name"`
	Result      bool   `json:"result" bson:"result"`
	ThreatFound string `json:"threatFound" bson:"threatFound"`
}

// RulesetEntry is the service-level publishing unit: one canonical URL and
// its actual published verdict, nothing else from the submission document
// crosses this boundary. Handlers map entries onto the extension-facing
// rules ( models.DNRRule ) when they serve the ruleset.
type RulesetEntry struct {
	// URL is the canonicalized URL, identical to the stored record's.
	URL string `bson:"url" json:"url"`
	// Verdict is the record's stored verdict (malicious or suspicious; see
	// PublishedVerdicts). It is copied, never derived at read time.
	Verdict string `bson:"verdict" json:"verdict"`
}

// PublishedVerdicts is the eligibility vocabulary of the published ruleset: a
// stored record becomes a rule only when its verdict is in this list.
//
// The policy deliberately excludes the other verdicts:
//
//   - no_threat_detected is evidence that a URL is clean, not a rule to warn
//     about;
//   - inconclusive and unknown scanner evidence is never read as a threat
//     classification;
//   - records without any verdict (pending, failed, deprecated "submitted")
//     have no confirmed classification at all.
var PublishedVerdicts = []string{VerdictMalicious, VerdictSuspicious}

// DNRResourceTypes is the request-type list every published rule covers: a
// fixed, extension-agnostic set — a published verdict is evidence about a
// URL, not about which request type carried it.
var DNRResourceTypes = []string{
	"main_frame",
	"sub_frame",
	"script",
	"xmlhttprequest",
	"ping",
	"websocket",
	"webtransport",
}

// DNRAction is the action part of a published rule. Both published verdicts
// map onto the single "block" action: the ruleset exists to keep
// classified-threat URLs away, and every rule says exactly that.
type DNRAction struct {
	// Type is "block".
	Type string `json:"type"`
}

// DNRCondition is the condition part of a published rule: an adblock-style
// urlFilter plus the constant request types of DNRResourceTypes.
type DNRCondition struct {
	// URLFilter matches the assessed URL, built as ||host^path| (a bare
	// host becomes ||host^). See the get-all contract for the exact
	// construction.
	URLFilter string `json:"urlFilter"`
	// ResourceTypes is DNRResourceTypes, always the same list.
	ResourceTypes []string `json:"resourceTypes"`
	// IsURLFilterCaseSensitive is always true; the pattern is delivered
	// verbatim as stored.
	IsURLFilterCaseSensitive bool `json:"isUrlFilterCaseSensitive"`
}

// DNRRule is one dynamic declarativeNetRequest rule, in the exact shape a
// browser extension installs through updateDynamicRules — the ruleset is
// delivered verbatim for that purpose.
type DNRRule struct {
	// ID is the rule's identifier, 1..N over the published order. A rule
	// derived for a single URL (the check-url response's data.rule) has
	// no id: the client assigns one when adding it dynamically. The zero
	// value is omitted, so an extension cannot install an id-less rule by
	// accident.
	ID *int64 `json:"id,omitempty"`
	// Priority is 1 for every published rule.
	Priority int64 `json:"priority"`
	// Action is always "block".
	Action DNRAction `json:"action"`
	// Condition carries the URL match.
	Condition DNRCondition `json:"condition"`
}

// RulesetCollection holds the authoritative published version document.
const RulesetCollection = "ruleset_state"

// RulesetStateID pins the single version document. Upserts against this exact
// ID mean concurrent runs can never create a duplicate version document.
const RulesetStateID = "current"

// RulesetState is the stored version document. It is internal state: the
// version is served inside the get-all response, the digest and timestamps
// never leave the process.
//
// The digest is the SHA-256 fingerprint of the published entries as they were
// when the version was written. A read that cannot reproduce it refuses to
// serve instead of returning version and data from different snapshots.
type RulesetState struct {
	ID        string    `bson:"_id" json:"-"`
	Version   int64     `bson:"version" json:"-"`
	Digest    string    `bson:"digest" json:"-"`
	UpdatedAt time.Time `bson:"updatedAt" json:"-"`
}
