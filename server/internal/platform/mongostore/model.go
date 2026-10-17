package mongostore

import (
	"time"

	"cyberguard/server/internal/verdicts"
)

// Persistent models for CyberGuard AI.
//
// # Collections
//
// Three, deliberately separate:
//
//   - scans        lifecycle and provider submission metadata. High-churn: a
//     scan is updated on every state transition. Never TTL-deleted, because a
//     scan record is the audit trail for a provider submission.
//   - assessments  the normalised verdict cache, keyed by URL fingerprint.
//     Written once per completed analysis. Read on the hot path. TTL-deleted at
//     expiry, because its retention policy is explicitly "until expires_at".
//   - transient_urls  an encrypted raw URL that exists only long enough for a
//     worker to submit it. See ADR 0013 and transienturl.go.
//
// Keeping them apart means a status poll rewrites a small, hot document rather
// than the record the verdict cache reads, and verdict expiry is not entangled
// with scan lifecycle.
//
// # What is never stored
//
// A raw URL is never a field on Scan or Assessment. A provider API key is
// never a field on any document. Both are enforced by the absence of any
// corresponding BSON tag, and by TestDocumentsNeverCarryRawURLsOrKeys.

// ScanStatus is a point in the scan lifecycle.
//
// The vocabulary matches the ScanStatus enum in openapi.yaml and ADR 0011.
// It is deliberately independent of any verdict: a scan has no verdict until it
// reaches ScanCompleted, and a failed scan has none at all.
type ScanStatus string

const (
	// ScanQueued means the scan is accepted and awaiting a worker.
	ScanQueued ScanStatus = "queued"
	// ScanRunning means a worker has claimed it and a submission is in flight.
	ScanRunning ScanStatus = "running"
	// ScanCompleted means a terminal provider report was normalised and stored.
	ScanCompleted ScanStatus = "completed"
	// ScanFailed means the scan ended in error.
	ScanFailed ScanStatus = "failed"
	// ScanTimedOut means the scan exceeded its deadline.
	ScanTimedOut ScanStatus = "timed_out"
	// ScanExpired means the stored verdict passed expires_at and must not be
	// served as fresh.
	ScanExpired ScanStatus = "expired"
)

// activeStatuses are the statuses in which a scan still holds a provider
// submission or is waiting to make one.
//
// This set is load-bearing twice: it defines the partial unique index that
// guarantees one active scan per fingerprint, and it defines whether a scan may
// be dequeued. Changing it changes correctness, not just an optimisation.
var activeStatuses = []ScanStatus{ScanQueued, ScanRunning}

// IsActive reports whether the scan is still in flight.
func (s ScanStatus) IsActive() bool {
	for _, a := range activeStatuses {
		if s == a {
			return true
		}
	}
	return false
}

// allStatuses is every defined scan status, in lifecycle order.
//
// It is the single list Valid and All derive from, so adding a status cannot
// update one and forget the other.
var allStatuses = []ScanStatus{
	ScanQueued, ScanRunning, ScanCompleted, ScanFailed, ScanTimedOut, ScanExpired,
}

// All returns every defined scan status.
//
// It exists so consumers can enumerate the vocabulary rather than restate it.
// The OpenAPI drift test uses it to assert the documented ScanStatus enum
// matches the code: a status added here but not to the contract, or vice
// versa, is exactly the drift that check exists to catch.
func All() []ScanStatus {
	out := make([]ScanStatus, len(allStatuses))
	copy(out, allStatuses)
	return out
}

// Valid reports whether s is a defined status.
func (s ScanStatus) Valid() bool {
	for _, a := range allStatuses {
		if s == a {
			return true
		}
	}
	return false
}

// Evidence is one bounded, human-readable reason for a verdict.
//
// Type and Summary are provider-derived but normalised. Summary is capped by
// the caller, because it reaches the browser extension and must not be an
// unbounded channel.
type Evidence struct {
	Type    string `bson:"type"    json:"type"`
	Summary string `bson:"summary" json:"summary"`
}

// Scan is the lifecycle record for one URL check.
//
// It is the audit trail: it records that a submission happened, to which
// provider, under which provider job ID, and how it ended. It therefore has no
// TTL index — see docs/data-model.md §6.
type Scan struct {
	// ScanID is CyberGuard's own identifier and the document _id.
	ScanID string `bson:"_id" json:"scan_id"`

	// URLFingerprint is the HMAC-SHA-256 of the canonical URL. It is the only
	// handle on the URL that ever reaches disk.
	URLFingerprint string `bson:"url_fingerprint" json:"-"`

	// Hostname and RegistrableDomain are retained for host-level lookup. They
	// are far less identifying than a full URL but are not anonymous.
	Hostname          string `bson:"hostname,omitempty"          json:"-"`
	RegistrableDomain string `bson:"registrable_domain,omitempty" json:"-"`

	Status      ScanStatus `bson:"status"       json:"status"`
	Attempts    int        `bson:"attempts"     json:"attempts"`
	MaxAttempts int        `bson:"max_attempts" json:"-"`

	// Provider submission metadata. Populated as soon as the provider responds,
	// and retained afterwards so a restarted worker can resume polling instead
	// of submitting again.
	Provider              string     `bson:"provider,omitempty"                  json:"provider,omitempty"`
	ProviderScanID        string     `bson:"provider_scan_id,omitempty"          json:"-"`
	ProviderSubmissionID  string     `bson:"provider_submission_id,omitempty"    json:"-"`
	ProviderState         string     `bson:"provider_state,omitempty"           json:"-"`
	ProviderEnvironmentID *int       `bson:"provider_environment_id,omitempty"   json:"-"`
	ProviderErrorType     string     `bson:"provider_error_type,omitempty"       json:"-"`
	ProviderErrorOrigin   string     `bson:"provider_error_origin,omitempty"     json:"-"`
	SubmittedAt           *time.Time `bson:"submitted_at,omitempty"             json:"submitted_at,omitempty"`

	// Scheme and PathPrefix carry the bounded URL detail a ruleset rule needs
	// to be built at a scope narrower than the whole host.
	//
	// They exist only while the scan is in flight. Once the verdict is known
	// the worker copies them onto the assessment — but only if the verdict is
	// malicious — and clears them here, so the long-lived audit trail does not
	// retain a path fragment for every URL ever scanned.
	//
	// The query string is never stored, at any point: it routinely carries
	// session tokens. See ADR 0018.
	Scheme     string `bson:"scheme,omitempty"      json:"-"`
	PathPrefix string `bson:"path_prefix,omitempty" json:"-"`

	// LastErrorCode is a CyberGuard-owned safe code. It never contains provider
	// prose, because it can reach a client-visible response.
	LastErrorCode string `bson:"last_error_code,omitempty" json:"error_code,omitempty"`

	CreatedAt   time.Time  `bson:"created_at"    json:"created_at"`
	UpdatedAt   time.Time  `bson:"updated_at"    json:"updated_at"`
	StartedAt   *time.Time `bson:"started_at,omitempty"   json:"-"`
	CompletedAt *time.Time `bson:"completed_at,omitempty" json:"-"`
}

// Assessment is a normalised, cached security verdict for one exact URL.
//
// The document _id is the URL fingerprint, which makes uniqueness and the hot
// lookup path the same operation. This is a deliberate improvement over
// docs/data-model.md §2, which specified a separate surrogate _id plus a unique
// index: a primary-key fetch is strictly cheaper and cannot drift out of sync
// with the unique index.
type Assessment struct {
	// URLFingerprint is the document _id and the HMAC of the canonical URL.
	URLFingerprint string `bson:"_id" json:"-"`

	// ScanID links back to the scan that produced this verdict.
	ScanID string `bson:"scan_id" json:"scan_id"`

	Hostname          string `bson:"hostname,omitempty"          json:"-"`
	RegistrableDomain string `bson:"registrable_domain,omitempty" json:"-"`

	// Scheme and PathPrefix exist solely so a rule can be built at a scope
	// narrower than the whole host.
	//
	// They are written **only** when the verdict is malicious — the single
	// verdict the ruleset policy can ever act on. A benign, inconclusive or
	// failed finding stores neither, so the URL detail exists only where it
	// could plausibly become a published rule.
	//
	// This is a deliberate weakening of "raw URLs are never stored", and it is
	// the price of the policy's narrowest-defensible-rule requirement: a rule
	// for one exact URL needs that URL. Two mitigations apply. The **query
	// string is never stored**, because it carries session tokens; and only the
	// path is kept, never the scheme+host+query whole. See ADR 0018 — this
	// trade needs an explicit decision from the project owner.
	Scheme     string `bson:"scheme,omitempty"      json:"-"`
	PathPrefix string `bson:"path_prefix,omitempty" json:"-"`

	// Verdict is present only because an Assessment exists only once an
	// analysis completed. There is no document holding a verdict for a failed
	// scan, which is what makes "failed means clean" unrepresentable.
	Verdict verdicts.Verdict `bson:"verdict" json:"verdict"`

	Provider       string     `bson:"provider,omitempty"    json:"provider,omitempty"`
	ProviderScanID string     `bson:"provider_scan_id,omitempty" json:"-"`
	Evidence       []Evidence `bson:"evidence,omitempty"   json:"evidence,omitempty"`

	AnalyzedAt time.Time `bson:"analyzed_at" json:"analyzed_at"`
	// ExpiresAt drives both freshness checks and the TTL index.
	ExpiresAt time.Time `bson:"expires_at" json:"expires_at"`
	CreatedAt time.Time `bson:"created_at" json:"-"`
	UpdatedAt time.Time `bson:"updated_at" json:"-"`
}

// IsFresh reports whether the assessment may still be served as current.
func (a Assessment) IsFresh(now time.Time) bool {
	return now.Before(a.ExpiresAt)
}
