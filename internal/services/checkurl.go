// Package services orchestrates the two API operations: checking a URL and
// reading stored assessments back.
//
// CheckURL is a cache-first workflow:
//
//  1. The submitted URL is canonicalized once — the same canonical form is
//     used for the MongoDB lookup key (its SHA-256, the urlHash), for the
//     stored record and for the provider submission.
//  2. MongoDB is asked first. A completed, non-expired assessment is served
//     without any provider call. A pending record reuses its existing
//     provider ID instead of submitting the same URL again.
//  3. Only when no usable record exists is the URL submitted to
//     POST /quick-scan/url, exactly once per request.
//  4. The documented retrieval endpoint GET /quick-scan/{id} is polled with a
//     bounded timeout and a fixed interval until the provider reports
//     `finished: true`, the request deadline is reached (HTTP 202, verdict
//     stays null) or the provider fails.
//  5. A finished result is normalized under the documented policy in
//     verdict.go and persisted atomically; a completed assessment can never
//     be overwritten by an incomplete one.
//
// Concurrency: equivalent requests within one process are admitted one at a
// time per canonical URL (an in-process in-flight set — no queues, no
// workers), and cross-process duplicates are collapsed by the unique
// `uniq_url_hash` index: losing writers adopt the winner's record instead of
// creating a second submission.
//
// The service layer is where errors are mapped from provider- and
// store-specific shapes onto this API's stable error vocabulary, so handlers
// never touch provider errors directly.
package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"time"
	"unicode"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"

	"cyberguard/internal/hybridanalysis"
	"cyberguard/internal/models"
)

// Validation, pagination and policy bounds.
const (
	// MaxURLLength bounds a submitted URL. 2048 is a widely accepted de
	// facto limit; longer input is rejected before anything is parsed.
	MaxURLLength = 2048
	// DefaultLimit and MaxLimit bound get-all's page size.
	DefaultLimit = 20
	MaxLimit     = 100
	// MaxPage bounds the page parameter so a skip value can never overflow.
	MaxPage = 1_000_000

	// DefaultAssessmentTTL is how long a completed assessment may be served
	// from MongoDB before a fresh provider check happens.
	DefaultAssessmentTTL = 24 * time.Hour
	// DefaultPollInterval is the pause between result retrievals while one
	// request waits for the provider to finish.
	DefaultPollInterval = time.Second
	// DefaultWaitBudget is how long one request may keep retrieving a
	// result before answering HTTP 202; server WriteTimeout adds a margin
	// on top of it.
	DefaultWaitBudget = 30 * time.Second
)

// Error is a service-level failure with a stable code and HTTP status.
// Message is written for the API client and never contains provider prose, a
// URL, or the API key. The wrapped cause is for logs only.
type Error struct {
	Status  int
	Code    string
	Message string
	err     error
}

func (e *Error) Error() string { return e.Message }
func (e *Error) Unwrap() error { return e.err }

// Stable error codes.
const (
	CodeInvalidRequest     = "invalid_request"
	CodeValidationError    = "validation_error"
	CodeProviderMissingKey = "provider_not_configured"
	CodeProviderAuth       = "provider_auth_failed"
	CodeProviderRateLimit  = "provider_rate_limited"
	CodeProviderTimeout    = "provider_timeout"
	CodeProviderRejected   = "provider_rejected"
	CodeProviderUnavail    = "provider_unavailable"
	CodeProviderBadResp    = "provider_bad_response"
	CodeStoreUnavailable   = "store_unavailable"
	// CodeRequestInProgress covers the rare case of a request that waited
	// out a concurrent equivalent request and found no verifiable record to
	// serve; the client is asked to retry rather than the service submitting
	// a duplicated analysis.
	CodeRequestInProgress = "request_in_progress"
)

// URLAnalyzer is the provider behaviour the service needs. Declared here, on
// the consumer side, so tests substitute a fake without a real client.
type URLAnalyzer interface {
	QuickScanURL(ctx context.Context, rawURL string) (hybridanalysis.Result, error)
	GetQuickScanResult(ctx context.Context, quickScanID string) (hybridanalysis.Result, error)
}

// SubmissionStore is the persistence behaviour the service needs.
type SubmissionStore interface {
	FindByURLHash(ctx context.Context, urlHash string) (*models.Submission, error)
	FindByRawURL(ctx context.Context, url string) (*models.Submission, error)
	AdoptURLHash(ctx context.Context, id bson.ObjectID, urlHash string) (bool, error)
	InsertSubmission(ctx context.Context, sub *models.Submission) error
	SavePendingProgress(ctx context.Context, id bson.ObjectID, stage *models.Submission) (bool, error)
	SaveFinalResult(ctx context.Context, id bson.ObjectID, final *models.Submission) (bool, error)
	ResetForRescan(ctx context.Context, id bson.ObjectID, expiredBefore time.Time, stage *models.Submission) (bool, error)
	ListSubmissions(ctx context.Context, page, limit int) ([]models.Submission, int64, error)
}

// ServiceOptions carries the tunable policy values read from configuration.
// Zero fields fall back to the documented defaults above.
type ServiceOptions struct {
	// AssessmentTTL is how long a completed assessment stays reusable.
	AssessmentTTL time.Duration
	// PollInterval is the pause between result retrievals while waiting.
	PollInterval time.Duration
	// WaitBudget bounds the total wait for a finished result inside one
	// request. Requests that run out of budget are answered 202 pending.
	WaitBudget time.Duration
}

// Service wires one provider and one store together.
type Service struct {
	store         SubmissionStore
	analyzer      URLAnalyzer
	now           func() time.Time
	assessmentTTL time.Duration
	pollInterval  time.Duration
	waitBudget    time.Duration
	inflight      inflightSet
}

// New builds a Service. analyzer may be nil when no API key is configured;
// CheckURL then reports the provider as unconfigured instead of pretending.
//
// A nil *T passed as the interface is normalized to an untyped nil: a typed
// nil otherwise looks non-nil forever and would panic on first use, the
// failure Go's reflect makes cheap to rule out at construction.
func New(store SubmissionStore, analyzer URLAnalyzer, opts ServiceOptions) *Service {
	if analyzer != nil {
		if v := reflect.ValueOf(analyzer); v.Kind() == reflect.Pointer && v.IsNil() {
			analyzer = nil
		}
	}
	if opts.AssessmentTTL <= 0 {
		opts.AssessmentTTL = DefaultAssessmentTTL
	}
	if opts.PollInterval <= 0 {
		opts.PollInterval = DefaultPollInterval
	}
	if opts.WaitBudget <= 0 {
		opts.WaitBudget = DefaultWaitBudget
	}
	return &Service{
		store:         store,
		analyzer:      analyzer,
		now:           func() time.Time { return time.Now().UTC() },
		assessmentTTL: opts.AssessmentTTL,
		pollInterval:  opts.PollInterval,
		waitBudget:    opts.WaitBudget,
	}
}

// CheckURL handles one URL check under the cache-first flow described in the
// package comment.
//
// Nothing is stored when the provider fails: a failed submission leaves no
// record that could be mistaken for a successful result, and provider errors
// are never converted into a verdict.
func (s *Service) CheckURL(ctx context.Context, rawURL string) (*models.Submission, *Error) {
	canonical, err := ValidateURL(rawURL)
	if err != nil {
		return nil, &Error{Status: 422, Code: CodeValidationError, Message: err.Error()}
	}
	hash := canonicalURLHash(canonical)

	// One deadline covers the whole request: parallel waits, the submission
	// itself and the result retrieval draw from the same budget, so the
	// caller's configured deadline is really the request's deadline.
	deadline := s.now().Add(s.waitBudget)

	rec, serr := s.findRecord(ctx, canonical, hash)
	if serr != nil {
		return nil, serr
	}

	// A completed, non-expired assessment is served from MongoDB; the
	// provider is not contacted at all.
	if sub := s.serveable(rec); sub != nil {
		return sub, nil
	}

	// One in-flight canonical URL per process. A concurrent equivalent
	// request waits (within the same budget) and then serves whatever the
	// first one persisted, instead of submitting twice.
	release, acquired := s.inflight.acquire(ctx, hash, deadline)
	if !acquired {
		sub, serr := s.concurrentOutcome(ctx, canonical, hash)
		if serr != nil {
			return nil, serr
		}
		return sub, nil
	}
	defer release()

	// The record may have been created or completed by the peer while
	// waiting: honour what is stored now.
	rec, serr = s.findRecord(ctx, canonical, hash)
	if serr != nil {
		return nil, serr
	}
	if sub := s.serveable(rec); sub != nil {
		return sub, nil
	}

	// No provider call is possible without a key; be honest about that
	// rather than serving an analysis that cannot progress.
	if s.analyzer == nil {
		return nil, &Error{
			Status:  503,
			Code:    CodeProviderMissingKey,
			Message: "the analysis provider is not configured; set HYBRID_ANALYSIS_API_KEY",
		}
	}

	if rec != nil && rec.ProviderID != "" && s.now().Sub(rec.UpdatedAt) < s.assessmentTTL {
		// A pending submission exists for this URL and is still fresh.
		// Reuse its provider ID — never submit the same URL again — and
		// try to retrieve the final result through the documented
		// endpoint.
	} else {
		// Nothing reusable is stored. Submit once and either insert the
		// new record or reset the stale one for the new scan.
		rec, serr = s.submitAgain(ctx, rec, canonical, hash)
		if serr != nil {
			return nil, serr
		}
		if rec.IsCompleted() {
			// The submission itself reported `finished: true`; the
			// normalized verdict is already stored.
			return rec, nil
		}
		if rec.ProviderID == "" {
			return nil, &Error{
				Status:  503,
				Code:    CodeRequestInProgress,
				Message: "another request for this URL is being analysed; please retry shortly",
			}
		}
	}

	// Retrieve and persist the final result inside this request, bounded by
	// the request deadline.
	return s.waitForResult(ctx, rec, deadline)
}

// serveable returns the record when it may be served as a cached result
// without any provider interaction: a completed assessment whose data is
// still inside the cache lifetime. Anything else — nil, pending, expired —
// reports nil.
func (s *Service) serveable(rec *models.Submission) *models.Submission {
	if rec == nil || !rec.IsCompleted() {
		return nil
	}
	if s.now().Sub(rec.UpdatedAt) >= s.assessmentTTL {
		return nil
	}
	return rec
}

// findRecord looks a URL up by its canonical hash. Records written before URL
// hashing existed are adopted on first touch, so subsequent lookups and the
// unique index apply to them too.
func (s *Service) findRecord(ctx context.Context, canonical, hash string) (*models.Submission, *Error) {
	sub, err := s.store.FindByURLHash(ctx, hash)
	if err != nil {
		return nil, storeError(err)
	}
	if sub != nil {
		return sub, nil
	}

	// Legacy fallback: exact URL match on records without a urlHash.
	sub, err = s.store.FindByRawURL(ctx, canonical)
	if err != nil {
		return nil, storeError(err)
	}
	if sub == nil {
		return nil, nil
	}
	if _, err := s.store.AdoptURLHash(ctx, sub.ID, hash); err != nil {
		return nil, storeError(err)
	}
	return sub, nil
}

// concurrentOutcome decides what a request that timed out waiting for a peer
// should tell its client. It serves the record the peer persisted when one is
// readable, and otherwise honestly reports that another request is working.
func (s *Service) concurrentOutcome(ctx context.Context, canonical, hash string) (*models.Submission, *Error) {
	rec, serr := s.findRecord(ctx, canonical, hash)
	if serr != nil {
		return nil, serr
	}
	if rec != nil {
		return rec, nil
	}
	return nil, &Error{
		Status:  503,
		Code:    CodeRequestInProgress,
		Message: "another request for this URL is being analysed; please retry shortly",
	}
}

// submitAgain performs exactly one submission of the canonical URL.
//
// rec is the stored record for the URL, or nil when none exists. The two
// write shapes differ:
//
//   - no record: insert the fresh one. A duplicate-key violation means a
//     concurrent request won the insert; adopt its record rather than
//     creating a second submission.
//   - existing record: atomically reset it — clearing the old analysis and
//     pointing it at the new provider submission — under a guard that leaves
//     any record another request just completed or refreshed untouched; the
//     winner's record is served instead.
//
// The returned record is either the fresh submission, an adopted completed
// record, or an adopted pending record whose provider ID the caller may wait
// on.
func (s *Service) submitAgain(ctx context.Context, rec *models.Submission, canonical, hash string) (*models.Submission, *Error) {
	result, err := s.analyzer.QuickScanURL(ctx, canonical)
	if err != nil {
		return nil, mapProviderError(err)
	}

	now := s.now()
	stage := &models.Submission{
		URL:        canonical,
		URLHash:    hash,
		Provider:   models.ProviderName,
		ProviderID: result.ID,
		ScanType:   result.ScanType,
		Status:     models.StatusPending,
		CreatedAt:  now,
		UpdatedAt:  now,
	}
	if rec != nil {
		stage.ID = rec.ID
		stage.CreatedAt = rec.CreatedAt
		if stage.ScanType == "" {
			stage.ScanType = rec.ScanType
		}
	}
	applyResult(stage, result)

	if rec == nil {
		if err := s.store.InsertSubmission(ctx, stage); err != nil {
			if mongo.IsDuplicateKeyError(err) {
				// A concurrent request stored the same canonical URL
				// first: there must not be two records, and there must
				// not be a second submission, so serve the winner's.
				return s.adoptStored(ctx, canonical, hash)
			}
			return nil, storeError(err)
		}
		return stage, nil
	}

	// The stored record is stale — a pending past its usable lifetime, a
	// completed past the cache TTL, or a pending without a usable provider
	// ID. Replace it with the fresh submission. The guard guarantees a
	// record another request just completed or refreshed cannot be reset.
	matched, err := s.store.ResetForRescan(ctx, rec.ID, now.Add(-s.assessmentTTL), stage)
	if err != nil {
		return nil, storeError(err)
	}
	if !matched {
		return s.adoptStored(ctx, canonical, hash)
	}
	if stage.Finished {
		// The submission answered finished immediately; persist the final
		// state now so the record never reads "pending" in between.
		if _, ferr := s.store.SaveFinalResult(ctx, rec.ID, stage); ferr != nil {
			return nil, storeError(ferr)
		}
	}
	return stage, nil
}

// adoptStored re-reads the record after a write race and reports what the
// winner persisted: a completed record is served as-is, a pending record is
// handed back for result retrieval, anything else is an honest error.
func (s *Service) adoptStored(ctx context.Context, canonical, hash string) (*models.Submission, *Error) {
	stored, serr := s.findRecord(ctx, canonical, hash)
	if serr != nil {
		return nil, serr
	}
	if stored == nil || stored.ProviderID == "" {
		return nil, &Error{
			Status:  503,
			Code:    CodeRequestInProgress,
			Message: "another request for this URL is being analysed; please retry shortly",
		}
	}
	return stored, nil
}

// waitForResult retrieves the scan through GET /quick-scan/{id} until the
// provider reports `finished: true`, the request runs out of budget (the
// pending record is returned for an HTTP 202), or the provider fails
// permanently.
//
// Transient retrieval failures — unavailable, timeout, malformed body — are
// tolerated while budget remains, because the analysis keeps running
// provider-side; the last failure is reported, never swallowed, once the
// budget is gone. The record stays pending through all of it: no retrieval
// error ever becomes a verdict.
func (s *Service) waitForResult(ctx context.Context, rec *models.Submission, deadline time.Time) (*models.Submission, *Error) {
	var lastErr error

	for {
		result, err := s.analyzer.GetQuickScanResult(ctx, rec.ProviderID)
		if err != nil {
			lastErr = err

			// Permanent classes abort at once: credentials, provider
			// policy and rate limits do not heal by waiting, and rate
			// limits must be honoured the moment they occur.
			var rateLimit *hybridanalysis.RateLimitError
			if errors.As(err, &rateLimit) ||
				errors.Is(err, hybridanalysis.ErrAuth) ||
				errors.Is(err, hybridanalysis.ErrValidation) {
				return nil, mapProviderError(err)
			}
			if !s.budgetRemains(deadline) {
				return nil, mapProviderError(lastErr)
			}
		} else {
			stage := s.stageFromResult(result, rec)

			if result.Finished {
				matched, ferr := s.store.SaveFinalResult(ctx, rec.ID, stage)
				if ferr != nil {
					return nil, storeError(ferr)
				}
				if !matched {
					// Another request completed the record first; serve
					// what is stored rather than overwriting it.
					if stored, serr2 := s.findRecord(ctx, rec.URL, rec.URLHash); serr2 == nil && stored != nil {
						return stored, nil
					}
				}
				return stage, nil
			}

			// Persist the latest known status, so get-all reflects the
			// unfinished response without inventing a verdict. When the
			// guard refuses the write the record was completed by a peer;
			// honour the stored record.
			matched, perr := s.store.SavePendingProgress(ctx, rec.ID, stage)
			if perr != nil {
				return nil, storeError(perr)
			}
			if !matched {
				if stored, serr2 := s.findRecord(ctx, rec.URL, rec.URLHash); serr2 == nil && stored != nil && stored.IsCompleted() {
					return stored, nil
				}
			}
			rec = stage
		}

		if !s.budgetRemains(deadline) {
			// The request deadline is reached without a finished result:
			// the pending record is the honest answer, HTTP 202.
			return rec, nil
		}
		if !s.sleepInterval(ctx) {
			return rec, nil
		}
	}
}

// budgetRemains reports whether at least one further retrieval round fits
// before the deadline.
func (s *Service) budgetRemains(deadline time.Time) bool {
	return s.now().Add(s.pollInterval).Before(deadline)
}

// sleepInterval waits one poll interval, returning false when the client or
// deadline interrupted the wait.
func (s *Service) sleepInterval(ctx context.Context) bool {
	timer := time.NewTimer(s.pollInterval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// stageFromResult merges a retrieval response onto the known record,
// preserving the identity fields the retrieval itself does not carry. The
// verdict is derived only here and only for finished responses.
func (s *Service) stageFromResult(result hybridanalysis.Result, base *models.Submission) *models.Submission {
	stage := &models.Submission{
		ID:         base.ID,
		URL:        base.URL,
		URLHash:    base.URLHash,
		Provider:   models.ProviderName,
		ProviderID: base.ProviderID,
		ScanType:   base.ScanType,
		Status:     models.StatusPending,
		CreatedAt:  base.CreatedAt,
		UpdatedAt:  s.now(),
	}
	applyResult(stage, result)
	return stage
}

// applyResult transfers the provider-reported fields onto a stage. The
// verdict is derived only from a `finished: true` response, via the
// documented normalization policy; anything else keeps Verdict nil.
func applyResult(stage *models.Submission, result hybridanalysis.Result) {
	if result.SHA256 != "" {
		stage.SHA256 = result.SHA256
	}
	if result.Scanners != nil {
		stage.Scanners = result.Scanners
	}
	if len(result.ScannersV2) > 0 {
		stage.ScannersV2 = result.ScannersV2
	}
	if result.Reports != nil {
		stage.Reports = result.Reports
	}
	stage.Finished = result.Finished
	if result.Finished {
		stage.Status = models.StatusCompleted
		if verdict, ok := normalizeVerdict(result); ok {
			stage.Verdict = &verdict
		}
	}
}

// List returns one page of stored assessments, newest first.
func (s *Service) List(ctx context.Context, page, limit int) ([]models.Submission, models.Pagination, *Error) {
	if page < 1 {
		page = 1
	}
	if limit < 1 {
		limit = DefaultLimit
	}
	if limit > MaxLimit {
		limit = MaxLimit
	}
	if page > MaxPage {
		page = MaxPage
	}

	items, total, err := s.store.ListSubmissions(ctx, page, limit)
	if err != nil {
		return nil, models.Pagination{}, &Error{
			Status:  503,
			Code:    CodeStoreUnavailable,
			Message: "stored results could not be read; please retry",
			err:     err,
		}
	}
	return items, models.NewPagination(page, limit, total), nil
}

// mapProviderError turns a provider error into a safe API error.
//
// The message never quotes the provider: provider prose is untrusted and must
// not be echoed to a browser. The wrapped cause is preserved for logs.
func mapProviderError(err error) *Error {
	var rateLimit *hybridanalysis.RateLimitError
	if errors.As(err, &rateLimit) {
		return &Error{
			Status:  429,
			Code:    CodeProviderRateLimit,
			Message: "the analysis provider rate limited the request; please retry later",
			err:     err,
		}
	}

	switch {
	case errors.Is(err, hybridanalysis.ErrAuth):
		return &Error{
			Status:  502,
			Code:    CodeProviderAuth,
			Message: "the analysis provider rejected the configured API key",
			err:     err,
		}
	case errors.Is(err, hybridanalysis.ErrTimeout):
		return &Error{
			Status:  504,
			Code:    CodeProviderTimeout,
			Message: "the analysis provider did not respond in time; the analysis stays pending",
			err:     err,
		}
	case errors.Is(err, hybridanalysis.ErrValidation):
		return &Error{
			Status:  502,
			Code:    CodeProviderRejected,
			Message: "the analysis provider rejected the request",
			err:     err,
		}
	case errors.Is(err, hybridanalysis.ErrBadResponse):
		return &Error{
			Status:  502,
			Code:    CodeProviderBadResp,
			Message: "the analysis provider returned an unexpected response",
			err:     err,
		}
	case errors.Is(err, hybridanalysis.ErrUnavailable):
		return &Error{
			Status:  502,
			Code:    CodeProviderUnavail,
			Message: "the analysis provider is unavailable; please retry later",
			err:     err,
		}
	case errors.Is(err, hybridanalysis.ErrNotConfigured):
		return &Error{
			Status:  503,
			Code:    CodeProviderMissingKey,
			Message: "the analysis provider is not configured; set HYBRID_ANALYSIS_API_KEY",
			err:     err,
		}
	default:
		return &Error{
			Status:  502,
			Code:    CodeProviderUnavail,
			Message: "the analysis provider request failed",
			err:     err,
		}
	}
}

// storeError wraps a persistence failure.
func storeError(err error) *Error {
	return &Error{
		Status:  503,
		Code:    CodeStoreUnavailable,
		Message: "stored results could not be accessed; please retry",
		err:     err,
	}
}

// ValidateURL enforces the API's URL contract and returns the canonical form
// used for the cache lookup, the stored record and the provider submission:
//
//   - whitespace-trimmed, bounded by MaxURLLength, no control characters;
//   - http or https only, with a non-empty host;
//   - the scheme and host lowercased, a default port removed and the
//     fragment removed;
//   - everything else — path, query string, userinfo, non-default ports —
//     preserved byte for byte, so URLs whose query strings carry signatures,
//     such as presigned storage links, still validate.
//
// The same canonicalization runs at lookup time and when storing, so
// "HTTPS://Example.com:443/#frag" and "https://example.com" hit one cache
// entry.
func ValidateURL(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	switch {
	case trimmed == "":
		return "", fmt.Errorf("url is required")
	case len(trimmed) > MaxURLLength:
		return "", fmt.Errorf("url is too long (maximum %d characters)", MaxURLLength)
	case strings.IndexFunc(trimmed, unicode.IsControl) >= 0:
		return "", fmt.Errorf("url contains control characters")
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("url is malformed")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "":
		return "", fmt.Errorf("url must include a scheme (http or https)")
	case "http", "https":
		// Documented schemes only.
	default:
		return "", fmt.Errorf("url scheme %q is not supported; only http and https are allowed", scheme)
	}
	if u.Host == "" {
		return "", fmt.Errorf("url is missing a host")
	}

	// Canonical host: lowercased, scheme's default port removed, fragment
	// removed. u.Hostname()/u.Port() understand bracketed IPv6 literals.
	hostname := strings.ToLower(u.Hostname())
	port := u.Port()
	if isDefaultPort(scheme, port) {
		port = ""
	}
	switch {
	case port != "" && strings.Contains(hostname, ":"):
		u.Host = "[" + hostname + "]:" + port
	case port != "":
		u.Host = hostname + ":" + port
	case strings.Contains(hostname, ":"):
		u.Host = "[" + hostname + "]"
	default:
		u.Host = hostname
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String(), nil
}

// isDefaultPort reports whether port is the scheme's default port.
func isDefaultPort(scheme, port string) bool {
	return (scheme == "http" && port == "80") || (scheme == "https" && port == "443")
}

// canonicalURLHash is the cache key of a canonical URL: the hex SHA-256 of
// its UTF-8 bytes. Hashing keeps the key bounded no matter how long the URL.
func canonicalURLHash(canonical string) string {
	sum := sha256.Sum256([]byte(canonical))
	return hex.EncodeToString(sum[:])
}

// inflightSet admits at most one CheckURL flow per canonical URL hash within
// the process. It is plain mutex-protected state — no queues, no workers, no
// cross-process coordination — and its waiters leave once the peer persists
// its record.
type inflightSet struct {
	mu   sync.Mutex
	busy map[string]chan struct{}
}

// acquire claims the hash, or waits (bounded by ctx and deadline) for the
// peer to release it and then claims. false means the wait ran out without a
// claim.
func (f *inflightSet) acquire(ctx context.Context, hash string, deadline time.Time) (func(), bool) {
	var timerC <-chan time.Time
	if remaining := time.Until(deadline); remaining > 0 {
		timer := time.NewTimer(remaining)
		defer timer.Stop()
		timerC = timer.C
	}

	for {
		f.mu.Lock()
		peer, busy := f.busy[hash]
		if !busy {
			if f.busy == nil {
				f.busy = make(map[string]chan struct{})
			}
			done := make(chan struct{})
			f.busy[hash] = done
			f.mu.Unlock()
			release := func() {
				f.mu.Lock()
				defer f.mu.Unlock()
				delete(f.busy, hash)
				close(done)
			}
			return release, true
		}
		f.mu.Unlock()

		select {
		case <-peer:
			// The peer released; loop to claim.
		case <-ctx.Done():
			return nil, false
		case <-timerC:
			return nil, false
		}
	}
}
