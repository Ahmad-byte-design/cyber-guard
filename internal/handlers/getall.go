package handlers

import (
	"net/http"
	"regexp"
	"strconv"

	"cyberguard/internal/services"
)

// GET /api/v1/get-all — version-aware ruleset sync.
//
// The frontend sends its currently installed ruleset version (?version=N);
// a missing version means a first-time client. When the stored authoritative
// version matches, the body is an empty array — the URL collection is not
// loaded at all. Otherwise, or for a first-time client, the complete
// published ruleset is delivered as a bare JSON array of dynamic
// declarativeNetRequest rules that a browser extension can install verbatim
// (updateDynamicRules).
//
// The body carries no envelope. Version and up-to-date status travel in the
// headers X-Ruleset-Version and X-Ruleset-Updated, so a client can read them
// without caring whether the array was empty because the ruleset is up to
// date or because nothing is published yet. Errors keep the common error
// envelope, and the version and data always belong to the same published
// snapshot (services.List guarantees that).
//
// The endpoint never contacts the provider, never mutates anything and never
// classifies anything: every rule is derived from an already-stored verdict
// under the publishing policy in internal/services/checkurl.go.

// Rule-set synchronization headers. X-Ruleset-Version is the authoritative
// published version; X-Ruleset-Updated is "false" only when the request's
// version matched it (the up-to-date fast path).
const (
	hdrRulesetVersion = "X-Ruleset-Version"
	hdrRulesetUpdated = "X-Ruleset-Updated"
)

// versionRE is the documented version format: a canonical non-negative
// decimal integer — digits only, no sign, no leading zeros ("0" itself is
// valid), at most 18 digits so it always fits an int64.
var versionRE = regexp.MustCompile(`^(0|[1-9][0-9]{0,17})$`)

func (s *Server) handleGetAll(w http.ResponseWriter, r *http.Request) {
	if !checkMethod(w, r, http.MethodGet) {
		return
	}

	version, serr := versionParam(r)
	if serr != nil {
		writeError(w, r, serr.Status, serr.Code, serr.Message)
		return
	}

	view, lerr := s.svc.List(r.Context(), version)
	if lerr != nil {
		s.logServiceError(r.Context(), "get-all", lerr)
		writeError(w, r, lerr.Status, lerr.Code, lerr.Message)
		return
	}

	w.Header().Set(hdrRulesetVersion, strconv.FormatInt(view.Version, 10))
	// X-Ruleset-Updated is false only on the up-to-date fast path; a
	// first-time client regains true.
	w.Header().Set(hdrRulesetUpdated, strconv.FormatBool(view.Updated))
	writeJSON(w, http.StatusOK, services.RulesetRules(view))
}

// versionParam parses the optional ?version=N parameter. Multiple
// occurrences are rejected the same way as a malformed value — the request
// must be unambiguous.
func versionParam(r *http.Request) (*int64, *services.Error) {
	// Query() merges repeated parameters with commas; Values() keeps the
	// occurrences separate so a duplicated parameter cannot hide.
	occurrences := r.URL.Query()["version"]
	switch len(occurrences) {
	case 0:
		// A first-time client: the complete ruleset is delivered.
		return nil, nil
	case 1:
	default:
		return nil, &services.Error{
			Status:  http.StatusBadRequest,
			Code:    services.CodeInvalidRequest,
			Message: versionBadMessage,
		}
	}
	value := occurrences[0]
	if !versionRE.MatchString(value) {
		return nil, &services.Error{
			Status:  http.StatusBadRequest,
			Code:    services.CodeInvalidRequest,
			Message: versionBadMessage,
		}
	}
	parsed, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return nil, &services.Error{
			Status:  http.StatusBadRequest,
			Code:    services.CodeInvalidRequest,
			Message: versionBadMessage,
		}
	}
	return &parsed, nil
}

// versionBadMessage spells the accepted range out completely, so no client
// has to guess why its version was refused.
const versionBadMessage = "version must be a non-negative integer (decimal digits only, no sign, no leading zeros, at most 18 digits)"
