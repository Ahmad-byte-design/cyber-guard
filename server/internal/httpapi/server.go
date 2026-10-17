// Package httpapi exposes the CyberGuard JSON API.
//
// Route surface follows docs/api-contract.md and openapi.yaml:
// POST /api/v1/check-url, GET /api/v1/get-url/{scanId},
// GET /api/v1/get-all, plus the liveness and readiness probes.
//
// Error responses are RFC 9457 problem details — see ADR 0015.
//
// The submitted-scan endpoints live in checkurl.go. This file holds the server
// wiring, the route table, middleware and the health probes.
package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/health"
	"cyberguard/server/internal/ratelimit"
	"cyberguard/server/internal/rulesetapi"
	"cyberguard/server/internal/scans"
)

// Dependencies are the collaborators a Server needs.
type Dependencies struct {
	Config config.Config
	Logger *slog.Logger
	// Health probes MongoDB for the readiness endpoint. Optional:
	// when nil, readiness evaluates configuration only.
	Health *health.Checker
	// Scans is the scan lifecycle. Optional: when nil the submission endpoints
	// report 503 rather than pretending to accept work they cannot process.
	Scans *scans.Service
	// Limiter evaluates the ADR 0014 abuse controls. Optional: when nil no rate
	// limit is enforced, which is only appropriate in tests.
	Limiter *ratelimit.Limiter
	// Rulesets serves the protection ruleset. Optional: when nil the endpoint
	// reports 503 rather than inventing an empty ruleset, which would read as
	// "you are protected by nothing" instead of "protection is unavailable".
	Rulesets *rulesetapi.Service
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// Server holds API dependencies.
type Server struct {
	cfg      config.Config
	logger   *slog.Logger
	health   *health.Checker
	scans    *scans.Service
	limiter  *ratelimit.Limiter
	rulesets *rulesetapi.Service
	now      func() time.Time
}

// NewServer builds a Server, filling in sane defaults for optional fields.
func NewServer(d Dependencies) *Server {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Server{
		cfg:      d.Config,
		logger:   d.Logger,
		health:   d.Health,
		scans:    d.Scans,
		limiter:  d.Limiter,
		rulesets: d.Rulesets,
		now:      d.Now,
	}
}

// route is one entry in the route surface.
type route struct {
	method  string
	pattern string
	// handler is a method expression, e.g. (*Server).handleLive, so the table
	// can name handlers without binding them to an instance.
	handler func(*Server, http.ResponseWriter, *http.Request)
	// gated marks a route that is only registered when its feature is enabled.
	//
	// The route stays in the table regardless, so the drift check against
	// openapi.yaml keeps comparing the full documented surface rather than
	// whichever subset one configuration happens to expose. A disabled route
	// is then genuinely absent from the router — a 404 from no route at all —
	// which is what "not served" should mean.
	gated bool
}

// routeTable is the single source of truth for the route surface.
//
// Keeping it as data rather than as scattered HandleFunc calls lets
// TestOpenAPISpecMatchesRoutes assert that every registered route is documented
// in openapi.yaml and vice versa, which is the mechanical drift check ADR 0015
// requires in place of code generation.
var routeTable = []route{
	// Liveness is process health only; readiness consults dependencies.
	{method: "GET", pattern: "/health/live", handler: (*Server).handleLive},
	{method: "GET", pattern: "/health/ready", handler: (*Server).handleReady},

	{method: "POST", pattern: "/api/v1/check-url", handler: (*Server).handleCheckURL},
	{method: "GET", pattern: "/api/v1/get-url/{scanId}", handler: (*Server).handleGetURL},
	// The same lookup expressed by URL. A POST body, not a path parameter:
	// a URL in a path is a URL in every access log between here and the client.
	{method: "POST", pattern: "/api/v1/get-url", handler: (*Server).handleGetURLByURL},
	{method: "GET", pattern: "/api/v1/get-all", handler: (*Server).handleGetAll},

	// Documentation. Gated on API_DOCS_ENABLED, but documented unconditionally:
	// the contract must describe the whole surface, not one configuration.
	{method: "GET", pattern: "/docs/", handler: (*Server).handleDocsUI, gated: true},
	{method: "GET", pattern: "/docs/assets/{name}", handler: (*Server).handleDocsAsset, gated: true},
	{method: "GET", pattern: "/openapi.yaml", handler: (*Server).handleOpenAPISpec, gated: true},
}

func (s *Server) registerRoutes(mux *http.ServeMux) {
	for _, rt := range routeTable {
		if rt.gated && !s.cfg.APIDocsEnabled {
			continue
		}
		// Go 1.22+ gives each iteration its own rt, so the closure capture
		// below is safe.
		mux.HandleFunc(rt.method+" "+rt.pattern, func(w http.ResponseWriter, r *http.Request) {
			rt.handler(s, w, r)
		})
	}
}

// Handler returns the fully wrapped http.Handler, including middleware.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	s.registerRoutes(mux)

	// A catch-all so that an unmatched path fails in this API's error format.
	//
	// Without it, http.ServeMux answers with Go's own 404: a plain-text body
	// and no content type a client can parse. Every other error this service
	// emits is RFC 9457, and a client that parses errors uniformly would trip
	// over exactly the one case it cannot predict — a mistyped path, which is
	// the most common mistake a client makes.
	//
	// "/" is the least specific pattern in the tree, so this never shadows a
	// registered route.
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found",
			"no endpoint matches this method and path")
	})

	return s.recoverer(s.requestID(s.accessLog(mux)))
}

// ---------------------------------------------------------------- handlers

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady reports whether the process can do useful work.
//
// Configuration checks are pure and always evaluated. Dependency checks —
// MongoDB — is delegated to the injected health.Checker and skipped
// entirely when none is supplied, which is the case in unit tests and in the
// pre-integration skeleton.
//
// Liveness deliberately does not consult any of this: a datastore outage must
// not cause an orchestrator to restart every replica.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	checks := []health.Report{{Name: "config", OK: true}}
	ready := true

	// Cryptographic configuration is a hard requirement, not a degraded
	// sub-check. Without the HMAC key there is no fingerprint and therefore no
	// cache lookup; without the encryption key a raw URL could only be stored
	// in the clear, which the privacy design forbids. Reporting ready in either
	// state would advertise a service that cannot honour its own contract.
	if !s.cfg.HasFingerprintKey() {
		checks = append(checks, health.Report{
			Name: "url_fingerprint_hmac_key", OK: false,
			Why: "URL_FINGERPRINT_HMAC_KEY is not set",
		})
		ready = false
	}
	if !s.cfg.HasEncryptionKey() {
		checks = append(checks, health.Report{
			Name: "url_encryption_key", OK: false,
			Why: "URL_ENCRYPTION_KEY is not set or is shorter than 32 bytes",
		})
		ready = false
	}
	if s.scans == nil {
		checks = append(checks, health.Report{
			Name: "scan_pipeline", OK: false,
			Why: "the scan lifecycle was not wired into this instance",
		})
		ready = false
	}

	if s.health != nil {
		depsReady, depReports := s.health.Run(r.Context())
		checks = append(checks, depReports...)
		if !depsReady {
			ready = false
		}
	}

	switch {
	case s.cfg.UsesMockProvider():
		// Mock mode is a complete, supported configuration, not a degradation:
		// analysis works, it just happens locally. Reporting it as unhealthy
		// would make the readiness endpoint cry wolf.
		checks = append(checks, health.Report{
			Name: "provider", OK: true,
			Why: "mock analysis provider; no external requests are made",
		})
	case s.cfg.HasProviderCredentials():
		checks = append(checks, health.Report{
			Name: "provider", OK: true,
			Why: "hybrid-analysis credentials are configured",
		})
	default:
		// A real provider with no credentials cannot analyse anything. It is a
		// degraded sub-check rather than a global failure, because cached
		// verdicts still work — but startup rejects this combination, so it is
		// reachable only in tests.
		checks = append(checks, health.Report{
			Name: "provider", OK: false,
			Why: "HYBRID_ANALYSIS_API_KEY is not set",
		})
	}

	if !ready {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "not_ready", "checks": checks,
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "checks": checks})
}

type checkURLRequest struct {
	URL string `json:"url"`
}

// -------------------------------------------------------------- middleware

type ctxKey int

const requestIDKey ctxKey = iota

// RequestIDFrom returns the correlation ID assigned to r, or "" if absent.
func RequestIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// requestID honours an inbound X-Request-ID so the extension and the service
// can share a correlation ID, otherwise mints a fresh one.
func (s *Server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimSpace(r.Header.Get("X-Request-ID"))
		if id == "" || len(id) > 64 {
			id = newRequestID()
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDKey, id)))
	})
}

// accessLog emits one structured line per request. It logs the path and
// status only: query strings and bodies can contain raw URLs, which section 11
// requires be kept out of logs.
func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := s.now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}

		next.ServeHTTP(rec, r)

		s.logger.InfoContext(r.Context(), "http request",
			slog.String("method", r.Method),
			slog.String("path", r.URL.Path),
			slog.Int("status", rec.status),
			slog.Int("bytes", rec.written),
			slog.Duration("duration", s.now().Sub(start)),
			slog.String("request_id", RequestIDFrom(r.Context())),
		)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.ErrorContext(r.Context(), "panic recovered",
					slog.Any("panic", rec),
					slog.String("request_id", RequestIDFrom(r.Context())),
					slog.String("stack", string(debug.Stack())),
				)
				writeError(w, r, http.StatusInternalServerError, "internal_error",
					"the service encountered an unexpected error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status      int
	written     int
	wroteHeader bool
}

func (s *statusRecorder) WriteHeader(code int) {
	if !s.wroteHeader {
		s.status = code
		s.wroteHeader = true
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Write(b []byte) (int, error) {
	if !s.wroteHeader {
		s.wroteHeader = true
	}
	n, err := s.ResponseWriter.Write(b)
	s.written += n
	return n, err
}

// ----------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// problemBase is the stable base URI for this deployment's problem types.
const problemBase = "https://cyberguard.example/problems/"

// problem is an RFC 9457 problem detail — see ADR 0015.
//
// Code is an extension member carried alongside the standard fields. A stable,
// low-cardinality string is more useful to a client branching on outcomes than
// a type URI it would have to pattern-match, so both are present.
//
// RequestID is an extension member that correlates the failure with the server
// logs. It is the only identifier permitted in a response body.
type problem struct {
	Type      string `json:"type"`
	Title     string `json:"title"`
	Status    int    `json:"status"`
	Detail    string `json:"detail,omitempty"`
	Instance  string `json:"instance,omitempty"`
	RequestID string `json:"request_id,omitempty"`
	Code      string `json:"code"`
}

// problemTitles maps a stable error code to its human-readable title, so a
// title is never typed ad hoc at a call site and the two cannot drift apart.
var problemTitles = map[string]string{
	"invalid_request":     "Invalid request",
	"validation_error":    "Validation error",
	"scan_not_found":      "Scan not found",
	"not_found":           "Not found",
	"not_ready":           "Service not ready",
	"rate_limited":        "Rate limited",
	"internal_error":      "Internal server error",
	"service_unavailable": "Service unavailable",
}

func titleFor(code string) string {
	if t, ok := problemTitles[code]; ok {
		return t
	}
	return "Request failed"
}

// writeError writes an RFC 9457 problem detail.
//
// detail is written for the end user. It must never contain a raw URL, an API
// key, a driver error, a stack trace, or an internal identifier other than
// request_id — TestRawURLNeverReachesLogs enforces that for logs and this
// shape keeps the same guarantee for responses.
func writeError(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	body := problem{
		Type:      problemBase + code,
		Title:     titleFor(code),
		Status:    status,
		Detail:    detail,
		RequestID: RequestIDFrom(r.Context()),
		Code:      code,
	}
	if r != nil && r.URL != nil {
		body.Instance = r.URL.Path
	}

	w.Header().Set("Content-Type", "application/problem+json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// decodeJSON reads a single JSON object with a hard size cap so a large or
// streaming body cannot exhaust memory.
func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	const maxBody = 8 << 10 // 8 KiB is generous for {"url": "..."}

	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType := strings.TrimSpace(strings.Split(ct, ";")[0])
		if mediaType != "application/json" {
			return errUnsupportedMediaType
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()

	if err := dec.Decode(dst); err != nil {
		return err
	}
	return nil
}

var errUnsupportedMediaType = errors.New("Content-Type must be application/json")

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102150405.000000")
	}
	return hex.EncodeToString(b[:])
}
