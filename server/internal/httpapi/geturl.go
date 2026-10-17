package httpapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"

	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/scans"
	"cyberguard/server/internal/urlintel"
)

// POST /api/v1/get-url — look up a URL's scan by URL instead of by ID.
//
// # Why a POST and not `GET /api/v1/get-url/{url}`
//
// A URL in a path is a URL in every log on the way. The access log of this
// service, the reverse proxy's, the load balancer's, a CDN's, and anything that
// records request lines for later would each hold it verbatim. That is exactly
// the exposure ADR 0013 exists to prevent, and the reason the endpoint takes an
// opaque `scanId` instead.
//
// A request body is not logged by default by any of those. So the same lookup,
// expressed as a POST carrying `{"url": "..."}`, keeps the URL out of every
// access log while still letting a client that has not kept a scan ID find its
// scan.
//
// The trade is that this endpoint cannot be linked to, prefetched or cached by a
// URL-aware intermediary. For an authenticated-by-absence, rate-limited
// diagnostic read that is the right way round.
//
// # This endpoint reads; it never starts anything
//
// It creates no scan, queues no work and contacts no provider. That is a
// deliberate boundary: a lookup that could trigger analysis would be a second
// submission endpoint with a different name, and would need its own quota
// accounting. A caller that wants a verdict uses POST /api/v1/check-url, which
// analyses what is missing and returns 200 when a fresh verdict already exists.
//
// # What it returns
//
// The most recent scan for the URL, in the identical response shape as
// GET /api/v1/get-url/{scanId} — including the rule that a verdict appears only
// for a completed scan whose assessment is still fresh. "Most recent" is
// resolved in one place, in the service layer, so the two endpoints cannot
// disagree.
func (s *Server) handleGetURLByURL(w http.ResponseWriter, r *http.Request) {
	// Same budget as polling by scan ID. It is the same read, expressed
	// differently, and must not be a way to spend more requests than the
	// endpoint it mirrors.
	if !s.allow(w, r, rateScopeClient, s.cfg.RateLimitPollPerMinute, time.Minute) {
		return
	}

	var req checkURLRequest
	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request",
			"request body must be a JSON object with a \"url\" field")
		return
	}

	if s.scans == nil {
		writeError(w, r, http.StatusServiceUnavailable, "not_ready",
			"the scan pipeline is not available on this instance")
		return
	}

	result, err := s.scans.LookupByURL(r.Context(), req.URL)
	if err != nil {
		s.writeLookupError(w, r, err)
		return
	}

	writeJSON(w, http.StatusOK, toScanResult(result))
}

// writeLookupError maps a lookup failure onto its documented status.
//
// The mapping mirrors writeSubmitError deliberately: the same URL can reach both
// endpoints, so the same URL must produce the same status and the same code
// whichever one is used. A client that submits and then polls should not see a
// validation error change shape between the two calls.
//
// detail is written for the end user and never contains the URL, a key or a
// driver message. Naming the address class of a refused target is deliberate: a
// caller learns that an internal address is not analysed, without the response
// becoming an oracle for what sits on the internal network.
func (s *Server) writeLookupError(w http.ResponseWriter, r *http.Request, err error) {
	switch {
	case urlintel.IsValidation(err):
		s.logger.WarnContext(r.Context(), "rejected lookup",
			slog.String("reason", err.Error()),
			slog.String("request_id", RequestIDFrom(r.Context())),
		)
		writeError(w, r, http.StatusUnprocessableEntity, "validation_error", err.Error())

	case errors.Is(err, scans.ErrDisallowedTarget):
		writeError(w, r, http.StatusUnprocessableEntity, "validation_error",
			"url: host is a loopback, private, reserved or internal address and cannot be submitted for analysis")

	case errors.Is(err, mongostore.ErrScanNotFound):
		// Deliberately the same code as a lookup by an unknown scan ID. A
		// client that cannot distinguish "never scanned" from "scanned but the
		// ID is wrong" gains nothing, and one code is one less thing to get
		// wrong.
		writeError(w, r, http.StatusNotFound, "scan_not_found",
			"no scan record exists for this url")

	case errors.Is(err, scans.ErrNotReady):
		writeError(w, r, http.StatusServiceUnavailable, "not_ready",
			"URL fingerprinting is unavailable; URL_FINGERPRINT_HMAC_KEY is not set")

	case errors.Is(err, context.DeadlineExceeded):
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable",
			"the request timed out before it could be answered")

	default:
		s.logger.ErrorContext(r.Context(), "looking up a scan by url failed",
			slog.String("reason", err.Error()),
			slog.String("request_id", RequestIDFrom(r.Context())),
		)
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable",
			"the scan status could not be read; please retry")
	}
}
