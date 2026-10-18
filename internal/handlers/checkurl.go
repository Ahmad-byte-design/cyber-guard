package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"

	"cyberguard/internal/hybridanalysis"
	"cyberguard/internal/services"
)

// POST /api/v1/check-url — check a URL against the cache and the provider's
// quick scan.
//
// A completed assessment — returned from the cache or obtained inside this
// request — is HTTP 200. An analysis that has not finished when the request's
// budget runs out is HTTP 202 with status "pending" and a null verdict: the
// provider accepted the scan, and a later request through the same endpoint
// reuses its provider ID instead of submitting again.

func (s *Server) handleCheckURL(w http.ResponseWriter, r *http.Request) {
	if !checkMethod(w, r, http.MethodPost) {
		return
	}

	body, perr := readJSONBody(w, r)
	if perr != nil {
		writeError(w, r, http.StatusBadRequest, services.CodeInvalidRequest,
			"request body must be a JSON object with a \"url\" field")
		return
	}

	// The body must be an object. Decoding into a map (not a struct) keeps
	// the field-level decisions in this handler, where the tests pin their
	// precedence: a body without "url" goes to the service validation (422),
	// a body carrying "url" plus anything else is a malformed request (400).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		writeError(w, r, http.StatusBadRequest, services.CodeInvalidRequest,
			"request body must be a JSON object with a \"url\" field")
		return
	}

	submitted := ""
	if _, ok := raw["url"]; ok {
		if len(raw) > 1 {
			writeError(w, r, http.StatusBadRequest, services.CodeInvalidRequest,
				"request body must contain only the \"url\" field")
			return
		}
		if err := json.Unmarshal(raw["url"], &submitted); err != nil {
			writeError(w, r, http.StatusBadRequest, services.CodeInvalidRequest,
				"\"url\" must be a string")
			return
		}
	}
	// An absent "url" key falls through with an empty value, so the service's
	// validation owns the "url is required" failure (422) just like an empty
	// string would.

	sub, serr := s.svc.CheckURL(r.Context(), submitted)
	if serr != nil {
		if retry := s.logServiceError(r.Context(), "check-url", serr); retry > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(retry))
		}
		writeError(w, r, serr.Status, serr.Code, serr.Message)
		return
	}

	status := http.StatusOK
	message := "URL analysis completed"
	if !sub.IsCompleted() {
		status = http.StatusAccepted
		message = "Analysis is still in progress"
	}
	// The rule lets an extension install its block immediately, without
	// waiting for the next get-all sync. Only a confirmed threat carries
	// one (see services.DNRRuleFor); clean and pending responses have no
	// rule field at all.
	sub.Rule = services.DNRRuleFor(sub)
	writeOK(w, status, message, sub)
}

// logServiceError logs the underlying cause of a service error and returns
// the provider's Retry-After hint, when there is one.
//
// The cause is server-side information; the client receives only the safe
// message carried by the Error itself.
func (s *Server) logServiceError(ctx context.Context, op string, serr *services.Error) int {
	cause := errors.Unwrap(serr)
	if cause == nil {
		cause = errors.New(serr.Code)
	}

	log := s.logger.WarnContext
	if serr.Status >= 500 {
		log = s.logger.ErrorContext
	}
	log(ctx, op+" failed",
		slog.String("code", serr.Code),
		slog.String("reason", cause.Error()),
		slog.String("request_id", RequestIDFrom(ctx)),
	)

	var rateLimit *hybridanalysis.RateLimitError
	if errors.As(cause, &rateLimit) && rateLimit.RetryAfter > 0 {
		seconds := int(rateLimit.RetryAfter.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		return seconds
	}
	return 0
}
