package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	contract "cyberguard/server"
	"cyberguard/server/internal/config"
	"cyberguard/server/internal/httpapi/docs"
	"cyberguard/server/internal/memstore"
)

// The documentation endpoints.
//
// These are the only endpoints that serve something other than scan data, and
// they are the ones a reader is most likely to reach for during an incident —
// which is exactly when the rest of the service may be degraded. They therefore
// touch no datastore, and the tests below hold them to that.

// docsServer builds a server with documentation explicitly on or off.
//
// It mirrors newTestServer but sets the one setting these tests vary, so the
// documentation endpoints are exercised through the real router and the real
// middleware rather than by calling a handler directly.
func docsServer(t *testing.T, enabled bool) http.Handler {
	t.Helper()

	cfg := testConfig(string(testKey))
	cfg.APIDocsEnabled = enabled

	store, err := memstore.NewStore(testKey)
	if err != nil {
		t.Fatalf("build store: %v", err)
	}

	logger := slog.New(slog.NewJSONHandler(io.Discard, nil))
	rig := &testRig{
		store: store,
		queue: memstore.NewQueue(),
		logs:  &bytes.Buffer{},
		cfg:   cfg,
	}
	return rig.build(t, logger, nil)
}

// request builds a request carrying one header, for the conditional-GET checks.
func request(method, target, header, value string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	r.Header.Set(header, value)
	return r
}

func TestDocsUIServesAnHTMLPage(t *testing.T) {
	t.Parallel()

	rec := do(t, docsServer(t, true), http.MethodGet, "/docs/", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html", ct)
	}

	body := rec.Body.String()
	if !strings.Contains(body, `id="swagger-ui"`) {
		t.Error("the page has no Swagger UI mount point")
	}
}

// The page must load the specification from this server, not from a CDN. A
// documentation page that needs the internet to render is useless in exactly
// the situation an operator opens it.
func TestDocsUILoadsTheLocalSpecification(t *testing.T) {
	t.Parallel()

	rec := do(t, docsServer(t, true), http.MethodGet, "/docs/", "", "")
	body := rec.Body.String()

	if !strings.Contains(body, "../openapi.yaml") {
		t.Error("the page does not reference the locally served specification")
	}

	// Every script and stylesheet must be same-origin and relative.
	for _, external := range []string{"//unpkg.com", "//cdn.", "https://cdn", "http://cdn"} {
		if strings.Contains(body, external) {
			t.Errorf("the page loads an asset from %q; assets must be vendored", external)
		}
	}
	if strings.Contains(body, "http://127.0.0.1:8080/assets") ||
		strings.Contains(body, "http://localhost:8080/assets") {
		t.Error("the page hard-codes an absolute asset URL, which breaks behind a proxy")
	}
}

// The specification must be retrievable at the documented path, and it must be
// the committed document.
func TestOpenAPISpecIsServedAndMatchesTheCommittedFile(t *testing.T) {
	t.Parallel()

	rec := do(t, docsServer(t, true), http.MethodGet, "/openapi.yaml", "", "")

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/yaml") {
		t.Errorf("Content-Type = %q, want application/yaml", ct)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Errorf("X-Content-Type-Options = %q, want nosniff", got)
	}

	if rec.Body.String() != string(contract.OpenAPISpec) {
		t.Error("the served specification differs from the embedded document")
	}
}

// A client must be able to verify it has the current document.
func TestOpenAPISpecSupportsConditionalRequests(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	first := do(t, h, http.MethodGet, "/openapi.yaml", "", "")
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("no ETag on the specification")
	}

	second := httptest.NewRecorder()
	h.ServeHTTP(second, request(http.MethodGet, "/openapi.yaml", "If-None-Match", etag))
	if second.Code != http.StatusNotModified {
		t.Errorf("a matching If-None-Match returned %d, want 304", second.Code)
	}
	if second.Body.Len() != 0 {
		t.Errorf("a 304 carried %d bytes of body", second.Body.Len())
	}
}

// The vendored assets must be served with their real types, because Swagger UI
// refuses to execute a script served as anything but JavaScript.
func TestDocsAssetsAreServedWithCorrectContentTypes(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	want := map[string]string{
		"swagger-ui.css":                  "text/css",
		"swagger-ui-bundle.js":            "text/javascript",
		"swagger-ui-standalone-preset.js": "text/javascript",
		"favicon-16x16.png":               "image/png",
		"favicon-32x32.png":               "image/png",
	}

	for name, contentType := range want {
		t.Run(name, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, "/docs/assets/"+name, "", "")
			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, contentType) {
				t.Errorf("Content-Type = %q, want %s", ct, contentType)
			}
			if rec.Body.Len() == 0 {
				t.Error("the asset is empty")
			}
		})
	}

	// Every asset the page loads must actually be served, or the UI renders
	// unstyled and inert.
	page := do(t, h, http.MethodGet, "/docs/", "", "").Body.String()
	for _, name := range docs.AssetNames() {
		if !strings.Contains(page, name) {
			continue
		}
		if rec := do(t, h, http.MethodGet, "/docs/assets/"+name, "", ""); rec.Code != http.StatusOK {
			t.Errorf("the page loads %q but it returns %d", name, rec.Code)
		}
	}
}

// An unknown asset name must not be served, and must be reported in this API's
// own error format rather than Go's default plain text — a client that parses
// errors uniformly should not trip over one endpoint.
func TestUnknownDocsAssetIsAProblemDocument(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	// ".." is in the list to prove traversal cannot reach the filesystem.
	// http.ServeMux cleans an unclean path and redirects to the cleaned one,
	// which is the correct and safe behaviour; what matters is that following
	// that redirect yields no content. The check therefore follows the
	// redirect and asserts the final outcome rather than the status code of
	// the first hop.
	for _, name := range []string{"swagger-ui.js", "../../etc/passwd", "index.html", "assets"} {
		t.Run(name, func(t *testing.T) {
			rec := serveFollowingRedirects(t, h, "/docs/assets/"+name)

			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d after following redirects, want 404", rec.Code)
			}
			if body := rec.Body.String(); strings.Contains(body, "root:") || strings.Contains(body, "/bin/") {
				t.Errorf("the traversal attempt returned filesystem content: %s", body)
			}
			ct := rec.Header().Get("Content-Type")
			if !strings.HasPrefix(ct, "application/problem+json") {
				t.Fatalf("Content-Type = %q, want a problem document", ct)
			}

			var p problem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if p.Code != "not_found" {
				t.Errorf("code = %q, want not_found", p.Code)
			}
		})
	}
}

// Turning documentation off must remove it entirely: a 404 from no registered
// route, not a handler that exists and declines.
func TestDocsAreAbsentWhenDisabled(t *testing.T) {
	t.Parallel()

	h := docsServer(t, false)

	for _, path := range []string{"/docs/", "/openapi.yaml", "/docs/assets/swagger-ui.css"} {
		rec := do(t, h, http.MethodGet, path, "", "")
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s returned %d with documentation disabled, want 404", path, rec.Code)
		}
	}
}

// Disabling documentation must not disturb the API it documents.
func TestDisablingDocsLeavesTheAPIIntact(t *testing.T) {
	t.Parallel()

	h := docsServer(t, false)

	// Liveness is independent of everything and answers 200.
	if rec := do(t, h, http.MethodGet, "/health/live", "", ""); rec.Code != http.StatusOK {
		t.Errorf("/health/live returned %d, want 200", rec.Code)
	}

	// get-all answers 503 because this rig has no ruleset service. That is the
	// correct answer and the point of the assertion: a wiring fault must be a
	// reported outage, not a panic and not an empty ruleset.
	rec := do(t, h, http.MethodGet, "/api/v1/get-all", "", "")
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("/api/v1/get-all returned %d, want 503", rec.Code)
	}

	// The API still accepts submissions and still reports a scan.
	submit := do(t, h, http.MethodPost, "/api/v1/check-url",
		`{"url":"https://example.test/login"}`, "application/json")
	if submit.Code != http.StatusAccepted && submit.Code != http.StatusOK {
		t.Errorf("check-url returned %d, want 200 or 202", submit.Code)
	}
}

// The existing routes keep working with documentation on, which is the default
// and therefore the case almost every deployment runs.
func TestAPIRoutesWorkWithDocsEnabled(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	rec := do(t, h, http.MethodPost, "/api/v1/check-url",
		`{"url":"https://example.test/login"}`, "application/json")
	if rec.Code != http.StatusAccepted && rec.Code != http.StatusOK {
		t.Fatalf("check-url returned %d, want 200 or 202", rec.Code)
	}

	// A scan ID must never come back as a URL.
	if strings.Contains(rec.Body.String(), "example.test") {
		t.Error("the response echoed the submitted URL")
	}
}

// Documentation must not become a way to disclose configuration or secrets.
func TestDocsDiscloseNoCredentials(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	for _, path := range []string{"/docs/", "/openapi.yaml"} {
		body := do(t, h, http.MethodGet, path, "", "").Body.String()

		for _, forbidden := range []string{
			"HYBRID_ANALYSIS_API_KEY=",
			"URL_ENCRYPTION_KEY=",
			"URL_FINGERPRINT_HMAC_KEY=",
			"Bearer ",
			"BEGIN PRIVATE KEY",
		} {
			if strings.Contains(body, forbidden) {
				t.Errorf("%s discloses %q", path, forbidden)
			}
		}
	}
}

// The default must be "on", so local development does not have to opt in and
// documentation cannot rot by being switched off and forgotten.
func TestAPIDocsDefaultEnabled(t *testing.T) {
	t.Setenv("API_DOCS_ENABLED", "")

	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.APIDocsEnabled {
		t.Error("API docs are off by default; local development should not have to opt in")
	}
}

func TestAPIDocsCanBeDisabled(t *testing.T) {
	for _, spelling := range []string{"false", "0", "no", "off", "FALSE"} {
		t.Run(spelling, func(t *testing.T) {
			t.Setenv("API_DOCS_ENABLED", spelling)

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if cfg.APIDocsEnabled {
				t.Errorf("API_DOCS_ENABLED=%q did not disable the documentation", spelling)
			}
		})
	}
}

func TestAPIDocsCanBeEnabledExplicitly(t *testing.T) {
	for _, spelling := range []string{"true", "1", "yes", "on"} {
		t.Run(spelling, func(t *testing.T) {
			t.Setenv("API_DOCS_ENABLED", spelling)

			cfg, err := config.Load()
			if err != nil {
				t.Fatalf("Load: %v", err)
			}
			if !cfg.APIDocsEnabled {
				t.Errorf("API_DOCS_ENABLED=%q did not enable the documentation", spelling)
			}
		})
	}
}

// serveFollowingRedirects issues a GET and follows up to five redirects,
// returning the final response.
//
// Go's ServeMux cleans a path containing ".." and issues a 307 to the cleaned
// form before any handler runs, which is precisely why traversal is safe here.
// A test asserting only "the first hop is 404" would be asserting an
// implementation detail; what matters is that following the redirect yields no
// filesystem content.
func serveFollowingRedirects(t *testing.T, h http.Handler, target string) *httptest.ResponseRecorder {
	t.Helper()

	var rec *httptest.ResponseRecorder
	for range 5 {
		rec = do(t, h, http.MethodGet, target, "", "")
		if rec.Code < 300 || rec.Code >= 400 || rec.Header().Get("Location") == "" {
			break
		}
		target = rec.Header().Get("Location")
	}
	return rec
}

// "/docs" must reach "/docs/". Swagger UI is loaded from the trailing-slash
// form, and its relative asset URLs resolve against the page URL, so a request
// without the slash has to be redirected rather than 404.
//
// This is worth pinning: the catch-all handler registered for unmatched paths
// is a "/" pattern, and a routing regression here would surface as a broken
// documentation page rather than a test failure.
func TestDocsWithoutTrailingSlashRedirects(t *testing.T) {
	t.Parallel()

	rec := do(t, docsServer(t, true), http.MethodGet, "/docs", "", "")

	if rec.Code != http.StatusMovedPermanently && rec.Code != http.StatusTemporaryRedirect {
		t.Fatalf("status = %d, want a redirect to /docs/", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "/docs/" {
		t.Errorf("Location = %q, want /docs/", got)
	}
}

// An unmatched path anywhere must fail in this API's error format.
func TestUnknownPathsAreProblemDocuments(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	for _, path := range []string{"/api/v1/nope", "/", "/api/v2/check-url", "/health"} {
		t.Run(path, func(t *testing.T) {
			rec := do(t, h, http.MethodGet, path, "", "")

			// A redirect is acceptable here: http.ServeMux issues one when a
			// request would match after path cleaning. Anything that is
			// neither a redirect nor a 404 is a routing bug.
			if rec.Code >= 300 && rec.Code < 400 {
				return
			}
			if rec.Code != http.StatusNotFound {
				t.Fatalf("status = %d, want 404", rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/problem+json") {
				t.Errorf("Content-Type = %q, want a problem document", ct)
			}
		})
	}
}
