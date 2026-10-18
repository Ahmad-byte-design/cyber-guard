// Package handlers exposes the CyberGuard AI JSON API.
//
// Route surface:
//
//	POST /api/v1/check-url   submit a URL to the provider's quick scan
//	GET  /api/v1/get-all     read stored submissions, newest first
//	GET  /health/live        process liveness
//	GET  /health/ready       readiness, including MongoDB
//	GET  /docs/              Swagger UI
//	GET  /openapi.yaml       the OpenAPI 3 contract
//
// Every response — success and error — is JSON with a "success" flag, so the
// website can parse outcomes uniformly.
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"runtime/debug"
	"strings"
	"time"

	"cyberguard/internal/config"
	"cyberguard/internal/services"
)

// Dependencies are the collaborators a Server needs.
type Dependencies struct {
	Config config.Config
	Logger *slog.Logger
	// Service performs both API operations.
	Service *services.Service
	// Ping probes MongoDB for the readiness endpoint.
	Ping func(ctx context.Context) error
	// Now is injectable for deterministic tests.
	Now func() time.Time
}

// Server holds API dependencies.
type Server struct {
	cfg    config.Config
	logger *slog.Logger
	svc    *services.Service
	ping   func(ctx context.Context) error
	now    func() time.Time
}

// New builds a Server, filling in sane defaults for optional fields.
func New(d Dependencies) *Server {
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	return &Server{cfg: d.Config, logger: d.Logger, svc: d.Service, ping: d.Ping, now: d.Now}
}

// Handler returns the fully wrapped http.Handler.
//
// Routes are registered as bare paths and method-checked inside the handler,
// which keeps every error — including 405 and 404 — in the same JSON shape.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/health/live", s.handleLive)
	mux.HandleFunc("/health/ready", s.handleReady)
	mux.HandleFunc("/api/v1/check-url", s.handleCheckURL)
	mux.HandleFunc("/api/v1/get-all", s.handleGetAll)
	mux.HandleFunc("/openapi.yaml", s.handleOpenAPISpec)
	mux.HandleFunc("/docs/", s.handleDocs)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		writeError(w, r, http.StatusNotFound, "not_found",
			"no endpoint matches this method and path")
	})

	return s.recoverer(s.requestID(s.accessLog(s.cors(mux))))
}

// ---------------------------------------------------------------- handlers

func (s *Server) handleLive(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

// handleReady reports whether the process can do useful work.
func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	checks := map[string]string{}

	if s.ping != nil {
		pingCtx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		err := s.ping(pingCtx)
		cancel()
		if err != nil {
			checks["mongodb"] = "unreachable"
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"status": "not_ready", "checks": checks,
			})
			return
		}
		checks["mongodb"] = "ok"
	} else {
		checks["mongodb"] = "not configured"
	}

	if s.cfg.HAAPIKey == "" {
		checks["provider"] = "HYBRID_ANALYSIS_API_KEY is not set"
	} else {
		checks["provider"] = "configured"
	}

	writeJSON(w, http.StatusOK, map[string]any{"status": "ready", "checks": checks})
}

// -------------------------------------------------------------- middleware

type ctxKey int

const requestIDKey ctxKey = iota

// RequestIDFrom returns the correlation ID assigned to r, or "" if absent.
func RequestIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(requestIDKey).(string)
	return v
}

// requestID honours an inbound X-Request-ID so the website and the service can
// share a correlation ID, otherwise mints a fresh one.
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

// accessLog emits one structured line per request.
//
// It logs the path only, never the query string: a submitted URL must not end
// up in a log line via a query parameter, now or after a future route change.
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

// recoverer turns a panic into a JSON 500 instead of a dropped connection.
func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.logger.ErrorContext(r.Context(), "panic recovered",
					slog.Any("panic", rec),
					slog.String("stack", string(debug.Stack())),
				)
				writeError(w, r, http.StatusInternalServerError, "internal_error",
					"the service encountered an unexpected error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// cors enforces the configured origin allow-list.
//
// An origin not on the list gets no CORS headers at all: the browser, not
// this server, blocks the read. That is the correct failure mode for an
// unexpected origin, and it is why no wildcard can leak in — the
// configuration loader rejects "*" outright.
func (s *Server) cors(next http.Handler) http.Handler {
	allowed := make(map[string]bool, len(s.cfg.CORSAllowedOrigins))
	for _, o := range s.cfg.CORSAllowedOrigins {
		allowed[strings.ToLower(o)] = true
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := strings.ToLower(strings.TrimRight(strings.TrimSpace(r.Header.Get("Origin")), "/"))
		if origin == "" || !allowed[origin] {
			next.ServeHTTP(w, r)
			return
		}

		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Add("Vary", "Origin")

		// A preflight is a bare OPTIONS with Access-Control-Request-Method.
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			w.Header().Set("Access-Control-Max-Age", "600")
			w.WriteHeader(http.StatusNoContent)
			return
		}

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

// checkMethod replies 405 unless r uses one of the allowed methods.
func checkMethod(w http.ResponseWriter, r *http.Request, allowed ...string) bool {
	for _, m := range allowed {
		if r.Method == m {
			return true
		}
	}
	w.Header().Set("Allow", strings.Join(allowed, ", "))
	writeError(w, r, http.StatusMethodNotAllowed, "method_not_allowed",
		"this endpoint accepts "+strings.Join(allowed, ", "))
	return false
}

// readJSONBody reads a bounded request body and validates the content type.
//
// The body is read first and parsed afterwards: json.Decoder stops reading
// once it has a complete value, so streaming a decoder over a capped reader
// would accept a "{ }" followed by megabytes of padding. Empty blobs stay
// forbidden — a missing body is not an empty request.
func readJSONBody(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	const maxBody = 8 << 10 // 8 KiB is generous for {"url": "..."}

	if ct := r.Header.Get("Content-Type"); ct != "" {
		mediaType := strings.TrimSpace(strings.Split(ct, ";")[0])
		if mediaType != "application/json" {
			return nil, errors.New("Content-Type must be application/json")
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	raw, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, err
	}
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, errors.New("request body must not be empty")
	}
	return raw, nil
}

func newRequestID() string {
	var b [12]byte
	if _, err := rand.Read(b[:]); err != nil {
		return time.Now().UTC().Format("20060102150405.000000")
	}
	return hex.EncodeToString(b[:])
}
