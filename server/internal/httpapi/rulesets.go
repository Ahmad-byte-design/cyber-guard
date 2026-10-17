package httpapi

import (
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"cyberguard/server/internal/rulesetapi"
)

// slogString keeps the log attribute construction readable at the call sites
// above; a two-line slog.String(...) per field would obscure the logic.
func slogString(k, v string) slog.Attr { return slog.String(k, v) }

// GET /api/v1/get-all — the published protection ruleset.
//
// Four documented behaviours are implemented here, and each exists because the
// alternative is worse:
//
//   - **version 0 with no rules** is a valid, truthful answer meaning "nothing
//     has been published yet". It is not an error, and it is what an empty
//     deployment returns.
//   - **`?version=N` matching the current version** returns `unchanged: true`
//     with an empty rule list, so a polling client transfers nothing.
//   - **`ETag` / `If-None-Match`** turn the same check into a 304 with no body
//     at all, for clients that prefer that over parsing JSON.
//   - **a client claiming a version *newer* than the server's** is told so via
//     `X-Ruleset-Rolled-Back: true`. That client installed a ruleset from a
//     different deployment; silently serving it an older one would leave it
//     protecting against rules this server has never heard of.
//
// This endpoint never publishes. Generation runs in the worker after a scan
// completes, so a burst of clients cannot turn a read endpoint into a write
// storm.

func (s *Server) handleGetAll(w http.ResponseWriter, r *http.Request) {
	// A nil service is a wiring fault, not an outage, and it must not become a
	// panic: the panic would be recovered into an opaque 500 with no useful
	// detail. It is also the state a deployment is in when RULESET_ENABLED is
	// false, so it is reachable in production rather than only in tests.
	//
	// 503 rather than an empty ruleset is the honest answer. An empty ruleset
	// reads as "you are protected by nothing", which is a claim about the
	// client's security; "protection is unavailable" is a claim about this
	// server, and a client can act on that one.
	if s.rulesets == nil {
		s.logger.ErrorContext(r.Context(), "the ruleset service is not configured",
			slogString("request_id", RequestIDFrom(r.Context())),
		)
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable",
			"the protection ruleset is not available on this deployment")
		return
	}

	snapshot, err := s.rulesets.Fetch(r.Context())
	if err != nil {
		s.logger.ErrorContext(r.Context(), "reading the ruleset failed",
			slogString("reason", err.Error()),
			slogString("request_id", RequestIDFrom(r.Context())),
		)
		writeError(w, r, http.StatusServiceUnavailable, "service_unavailable",
			"the ruleset could not be read; please retry")
		return
	}

	clientVersion, hasVersion, err := parseClientVersion(r)
	if err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request",
			"version must be a non-negative integer")
		return
	}

	// A client ahead of the server is on a different deployment. Say so
	// explicitly and serve the full snapshot anyway, so it can recover.
	rolledBack := hasVersion && clientVersion > snapshot.Version
	if rolledBack {
		w.Header().Set("X-Ruleset-Rolled-Back", "true")
		s.logger.InfoContext(r.Context(), "client reported a newer ruleset version",
			slog.Int64("client_version", clientVersion),
			slog.Int64("server_version", snapshot.Version),
		)
	}

	etag := fmt.Sprintf("\"v%d\"", snapshot.Version)

	if !rolledBack && hasVersion && clientVersion == snapshot.Version {
		// Conditional request first: a 304 costs nothing to parse.
		if matchETag(r, etag) {
			w.Header().Set("ETag", etag)
			w.Header().Set("X-Ruleset-Version", strconv.FormatInt(snapshot.Version, 10))
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("ETag", etag)
		w.Header().Set("X-Ruleset-Version", strconv.FormatInt(snapshot.Version, 10))
		writeJSON(w, http.StatusOK, rulesetResponse{
			Version:   snapshot.Version,
			Generated: snapshot.GeneratedAt.UTC().Format(time.RFC3339),
			Unchanged: true,
			Rules:     []rulesetapi.Rule{},
		})
		return
	}

	// A full snapshot is also conditional: an unchanged ETag means the client
	// already has it byte for byte.
	if matchETag(r, etag) {
		w.Header().Set("ETag", etag)
		w.Header().Set("X-Ruleset-Version", strconv.FormatInt(snapshot.Version, 10))
		w.WriteHeader(http.StatusNotModified)
		return
	}

	w.Header().Set("ETag", etag)
	w.Header().Set("X-Ruleset-Version", strconv.FormatInt(snapshot.Version, 10))
	w.Header().Set("Cache-Control", "no-cache")

	writeJSON(w, http.StatusOK, rulesetResponse{
		Version:   snapshot.Version,
		Generated: snapshot.GeneratedAt.UTC().Format(time.RFC3339),
		Rules:     snapshot.Rules,
	})
}

// rulesetResponse is the documented `Ruleset` schema.
//
// `unchanged` is omitted rather than sent as false, because the OpenAPI
// document declares it optional and a client distinguishing "unchanged" from
// "I sent no version" needs its absence to mean something.
type rulesetResponse struct {
	Version   int64             `json:"version"`
	Generated string            `json:"generated_at"`
	Unchanged bool              `json:"unchanged,omitempty"`
	Rules     []rulesetapi.Rule `json:"rules"`
}

// parseClientVersion reads the optional `version` query parameter.
//
// A malformed value is a 400 rather than being ignored. Treating an
// unparseable version as absent would serve a full snapshot to a client that
// believed it was up to date, and would hide the bug in the caller.
func parseClientVersion(r *http.Request) (version int64, present bool, err error) {
	raw := strings.TrimSpace(r.URL.Query().Get("version"))
	if raw == "" {
		return 0, false, nil
	}

	n, err := strconv.ParseInt(raw, 10, 64)
	if err != nil || n < 0 {
		return 0, true, fmt.Errorf("invalid version %q", raw)
	}
	return n, true, nil
}

// matchETag reports whether the request's If-None-Match covers etag.
//
// It handles the two forms a client may send: a bare entity tag, and a list
// including "*", which means "any representation will do".
func matchETag(r *http.Request, etag string) bool {
	header := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if header == "" {
		return false
	}

	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		switch {
		case candidate == "*":
			return true
		case candidate == etag:
			return true
		// Tolerate the weak form, which some clients send.
		case strings.TrimPrefix(candidate, "W/") == etag:
			return true
		}
	}
	return false
}
