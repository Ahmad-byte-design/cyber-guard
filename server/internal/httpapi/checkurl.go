package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/ratelimit"
	"cyberguard/server/internal/scans"
	"cyberguard/server/internal/urlintel"
	"cyberguard/server/internal/verdicts"
)

// The submitted-scan API: POST /api/v1/check-url and GET /api/v1/get-url/{scanId}.
//
// Response shapes are taken verbatim from openapi.yaml. That document is the
// contract — this file implements it, and the drift test in openapi_test.go
// keeps the route surface and the document in step.

// getURLPathPrefix is the status route, used to build the status_url a client
// polls. It is derived from the route table so the two cannot drift.
const getURLPathPrefix = "/api/v1/get-url/"

// cachedAssessmentResponse is the documented 200 body for a fresh verdict.
type cachedAssessmentResponse struct {
	ScanID  string `json:"scan_id"`
	Status  string `json:"status"`
	Cached  bool   `json:"cached"`
	Verdict string `json:"verdict"`

	Evidence   []mongostore.Evidence `json:"evidence,omitempty"`
	AnalyzedAt *time.Time            `json:"analyzed_at,omitempty"`
	ExpiresAt  *time.Time            `json:"expires_at,omitempty"`
}

// pendingAssessmentResponse is the documented 202 body: the work is accepted,
// and the client is told where to look.
type pendingAssessmentResponse struct {
	ScanID    string `json:"scan_id"`
	Status    string `json:"status"`
	Cached    bool   `json:"cached"`
	StatusURL string `json:"status_url"`

	// Retrying is a pointer so it is omitted rather than serialised as false.
	// The OpenAPI document declares it optional, and a client distinguishing
	// "first attempt" from "recovered" should see its absence as meaning the
	// former.
	Retrying *bool `json:"retrying,omitempty"`
}

// scanResultResponse is the documented 200 body of the status route.
//
// Verdict is a pointer so it is omitted entirely unless the scan completed.
// An absent verdict and an empty verdict are different facts, and flattening
// them would let a client read "no verdict" as "nothing found".
type scanResultResponse struct {
	ScanID   string                `json:"scan_id"`
	Status   string                `json:"status"`
	Verdict  *string               `json:"verdict,omitempty"`
	Provider string                `json:"provider,omitempty"`
	Evidence []mongostore.Evidence `json:"evidence,omitempty"`

	AnalyzedAt *time.Time `json:"analyzed_at,omitempty"`
	ExpiresAt  *time.Time `json:"expires_at,omitempty"`

	// ErrorCode is CyberGuard's own low-cardinality vocabulary. Provider error
	// text never reaches it.
	ErrorCode string `json:"error_code,omitempty"`
}

func (s *Server) handleCheckURL(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, rateScopeClient, s.cfg.RateLimitPerMinute, time.Minute) {
		return
	}

	var req checkURLRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request",
			"request body must be a JSON object with a \"url\" field")
		return
	}

	// Validation happens before anything is stored, so a rejected URL leaves no
	// fingerprint, no scan and no queue entry.
	if _, _, err := urlintel.Prepare([]byte(s.cfg.URLFingerprintHMACKey), req.URL); err != nil {
		if urlintel.IsValidation(err) {
			s.logger.WarnContext(r.Context(), "rejected submission",
				slog.String("reason", err.Error()),
				slog.String("request_id", RequestIDFrom(r.Context())),
			)
			writeError(w, r, http.StatusUnprocessableEntity, "validation_error", err.Error())
			return
		}
		writeError(w, r, http.StatusServiceUnavailable, "not_ready",
			"URL fingerprinting is unavailable; URL_FINGERPRINT_HMAC_KEY is not set")
		return
	}

	if s.scans == nil {
		writeError(w, r, http.StatusServiceUnavailable, "not_ready",
			"the scan pipeline is not available on this instance")
		return
	}

	outcome, err := s.scans.Submit(r.Context(), req.URL)
	if err != nil {
		s.writeSubmitError(w, r, err)
		return
	}

	if outcome.Cached && outcome.Assessment != nil {
		a := outcome.Assessment
		analyzed := a.AnalyzedAt
		expires := a.ExpiresAt
		writeJSON(w, http.StatusOK, cachedAssessmentResponse{
			ScanID:     a.ScanID,
			Status:     string(mongostore.ScanCompleted),
			Cached:     true,
			Verdict:    a.Verdict.String(),
			Evidence:   a.Evidence,
			AnalyzedAt: &analyzed,
			ExpiresAt:  &expires,
		})
		return
	}

	retrying := outcome.Retrying()
	body := pendingAssessmentResponse{
		ScanID:    outcome.Scan.ScanID,
		Status:    string(outcome.Scan.Status),
		Cached:    false,
		StatusURL: getURLPathPrefix + outcome.Scan.ScanID,
	}
	if retrying {
		body.Retrying = &retrying
	}
	writeJSON(w, http.StatusAccepted, body)
}

// writeSubmitError maps a lifecycle error onto its documented status.
//
// The mapping is explicit rather than a default-500 so an unexpected error
// still produces the generic internal_error body while a known condition
// produces the right code. detail is written for the end user and never
// contains a URL, a key or a driver message.
func (s *Server) writeSubmitError(w http.ResponseWriter, r *http.Request, err error) {
	var limit *scans.LimitError

	switch {
	case errors.As(err, &limit), errors.Is(err, scans.ErrRateLimited):
		retryAfter := 1
		if limit != nil {
			retryAfter = int(limit.RetryAfter / time.Second)
			if retryAfter < 1 {
				retryAfter = 1
			}
		}
		w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
		if limit != nil && limit.Limit > 0 {
			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Limit))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(limit.Remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(limit.Reset.Unix(), 10))
		}
		writeError(w, r, http.StatusTooManyRequests, "rate_limited",
			"too many submissions for this URL fingerprint")

	case urlintel.IsValidation(err):
		writeError(w, r, http.StatusUnprocessableEntity, "validation_error", err.Error())

	case errors.Is(err, scans.ErrDisallowedTarget):
		// The detail names the class of address, never the address itself: a
		// client must learn that a private target is refused without the
		// response becoming an oracle for what is on the internal network.
		writeError(w, r, http.StatusUnprocessableEntity, "validation_error",
			"url: host is a loopback, private, reserved or internal address and cannot be submitted for analysis")

	case errors.Is(err, scans.ErrNotReady):
		writeError(w, r, http.StatusServiceUnavailable, "not_ready",
			"the scan pipeline is not available on this instance")

	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable",
			"the request timed out before it could be recorded")

	default:
		s.logger.ErrorContext(r.Context(), "submitting a URL failed",
			slog.String("reason", err.Error()),
			slog.String("request_id", RequestIDFrom(r.Context())),
		)
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable",
			"the URL could not be accepted for analysis; please retry")
	}
}

func (s *Server) handleGetURL(w http.ResponseWriter, r *http.Request) {
	if !s.allow(w, r, rateScopeClient, s.cfg.RateLimitPollPerMinute, time.Minute) {
		return
	}

	scanID := strings.TrimSpace(r.PathValue("scanId"))
	if scanID == "" || len(scanID) > 64 {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "scanId is missing or malformed")
		return
	}
	if s.scans == nil {
		writeError(w, r, http.StatusNotFound, "scan_not_found", "no scan record exists for this id")
		return
	}

	result, err := s.scans.Lookup(r.Context(), scanID)
	switch {
	case errors.Is(err, mongostore.ErrScanNotFound):
		writeError(w, r, http.StatusNotFound, "scan_not_found", "no scan record exists for this id")
		return
	case err != nil:
		s.logger.ErrorContext(r.Context(), "looking up a scan failed",
			slog.String("reason", err.Error()),
			slog.String("request_id", RequestIDFrom(r.Context())),
		)
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable",
			"the scan status could not be read; please retry")
		return
	}

	writeJSON(w, http.StatusOK, toScanResult(result))
}

// toScanResult shapes a lifecycle result into the documented response.
//
// A verdict is attached only to a completed scan that has an assessment. An
// in-flight scan therefore carries no verdict field at all, which is the
// honest representation: nothing is known yet.
func toScanResult(result scans.Result) scanResultResponse {
	scan := result.Scan
	body := scanResultResponse{
		ScanID:    scan.ScanID,
		Status:    string(scan.Status),
		Provider:  scan.Provider,
		ErrorCode: scan.LastErrorCode,
	}

	if result.Assessment != nil {
		verdict := result.Assessment.Verdict.String()
		if !result.Assessment.Verdict.Valid() {
			// Defensive: the store rejects invalid verdicts on write, so this
			// is unreachable. If it ever fires, reporting "unknown" is still
			// better than emitting a value outside the documented enum.
			verdict = verdicts.Unknown.String()
		}
		analyzed := result.Assessment.AnalyzedAt
		expires := result.Assessment.ExpiresAt
		body.Verdict = &verdict
		body.Evidence = result.Assessment.Evidence
		body.AnalyzedAt = &analyzed
		body.ExpiresAt = &expires
	}
	return body
}

// -------------------------------------------------- rate limit enforcement

// rateScopeClient is the per-source request budget.
//
// The subject is a client address, which is the strongest identity available
// without a credential. X-Forwarded-For is deliberately ignored: honouring a
// client-supplied header would let any caller pick their own key and disable
// the limit entirely. A deployment behind a proxy must therefore either accept
// per-proxy limiting or supply the real address through a trusted mechanism.
const rateScopeClient = "client"

// allow evaluates one rate limit and writes the 429 if it is exceeded.
//
// When no limiter is configured — unit tests, and a process started without
// Redis — the check is skipped rather than failing the request. That is safe
// because the limiter is not the only control: deduplication is enforced in
// MongoDB, and the fingerprint budget is enforced by the scan lifecycle. Where
// Redis *is* configured, an outage fails closed inside the limiter itself.
func (s *Server) allow(w http.ResponseWriter, r *http.Request, scope string, limit int, window time.Duration) bool {
	if s.limiter == nil || limit <= 0 {
		return true
	}

	decision, err := s.limiter.Allow(r.Context(), scope, clientIdentity(r), limit, window)
	if err != nil {
		// Fail closed: without counters, an unguarded request could spend real
		// provider quota. 503 says "try later", which is both true and safe.
		s.logger.WarnContext(r.Context(), "rate limit could not be evaluated",
			slog.String("reason", err.Error()),
			slog.String("request_id", RequestIDFrom(r.Context())),
		)
		w.Header().Set("Retry-After", "5")
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable",
			"abuse protection is temporarily unavailable; please retry")
		return false
	}

	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(decision.Remaining))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(decision.Reset.Unix(), 10))

	if decision.Allowed {
		return true
	}

	retryAfter := int(decision.RetryAfter / time.Second)
	if retryAfter < 1 {
		retryAfter = 1
	}
	w.Header().Set("Retry-After", strconv.Itoa(retryAfter))
	writeError(w, r, http.StatusTooManyRequests, "rate_limited",
		"too many requests; slow down and retry later")
	return false
}

// clientIdentity extracts the rate-limit subject from a request.
//
// RemoteAddr's port is stripped so that every request from one host shares a
// budget regardless of its ephemeral source port.
func clientIdentity(r *http.Request) string {
	addr := r.RemoteAddr
	if i := strings.LastIndex(addr, ":"); i > 0 {
		addr = addr[:i]
	}
	addr = strings.Trim(addr, "[]")
	if addr == "" {
		return "unknown"
	}
	return addr
}

// NewFingerprintGuard builds the per-fingerprint submission budget hook that the
// scan lifecycle calls before creating a new scan.
//
// It is a constructor rather than middleware because the budget must be charged
// only when a submission is actually going to happen. Counting every request
// would charge a cache hit — which spends no provider quota — against the quota
// protection, and would make a repeatedly-visited benign URL look like an
// attack.
//
// A limiter outage returns an error, which aborts the submission before
// anything is written. That is the fail-closed behaviour ADR 0014 requires:
// proceeding unguarded would spend real quota.
func NewFingerprintGuard(limiter *ratelimit.Limiter, cfg config.Config) func(context.Context, string) error {
	limit := cfg.FingerprintSubmitLimit
	window := cfg.FingerprintSubmitWindow

	return func(ctx context.Context, fingerprint string) error {
		if limiter == nil || limit <= 0 {
			return nil
		}

		decision, err := limiter.Allow(ctx, "fingerprint", fingerprint, limit, window)
		if err != nil {
			return errors.Join(ratelimit.ErrUnavailable, err)
		}
		if decision.Allowed {
			return nil
		}
		return &scans.LimitError{
			Limit:      decision.Limit,
			Remaining:  decision.Remaining,
			Reset:      decision.Reset,
			RetryAfter: decision.RetryAfter,
		}
	}
}
