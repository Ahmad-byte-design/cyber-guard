// Package models defines the shapes that cross the API boundary and are
// persisted in MongoDB: the submission document and the pagination metadata.
//
// Provider-specific field names stop in the hybridanalysis package. Everything
// an API client or the database sees is named here, once.
package models

import (
	"math"
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

// Pagination is the metadata returned with every list response.
type Pagination struct {
	Page       int   `json:"page"`
	Limit      int   `json:"limit"`
	Total      int64 `json:"total"`
	TotalPages int64 `json:"totalPages"`
}

// NewPagination computes total pages for a page of size limit over total
// items. A total of zero yields zero pages, not one.
func NewPagination(page, limit int, total int64) Pagination {
	totalPages := int64(0)
	if limit > 0 && total > 0 {
		totalPages = int64(math.Ceil(float64(total) / float64(limit)))
	}
	return Pagination{Page: page, Limit: limit, Total: total, TotalPages: totalPages}
}
