// Package docs serves the OpenAPI contract and a Swagger UI for it, from the
// same binary that serves the API.
//
// # Why the assets are vendored
//
// Swagger UI is normally pulled from a CDN at page load. That is the wrong
// trade for this service: it makes the API contract unavailable exactly when it
// is most needed — an air-gapped deployment, an incident, a locked-down
// environment — and it makes the documentation's behaviour depend on a third
// party at runtime.
//
// So the distribution is vendored at a pinned version under `assets/` and
// embedded into the binary with `//go:embed`. Consequences worth stating:
//
//   - No network access is needed to serve or to build the documentation.
//   - The page renders identically in ten years, or changes only when someone
//     deliberately upgrades the pinned version in the repository.
//   - The binary grows by about 1.8 MB, which for an API server is noise.
//
// The vendored files are third-party Apache-2.0 code. `assets/LICENSE` is the
// upstream licence and `assets/VERSION` records the pinned release; an upgrade
// replaces the three script/style files, the favicons and VERSION together.
//
// # Why the asset list is an explicit map
//
// An embedded `http.FileServer` would be less code, but it also publishes a
// directory listing and serves whatever the embed happens to contain. Naming
// the five permitted files means the surface is exactly what was reviewed, and a
// file dropped into `assets/` by accident is not served until someone adds it
// here deliberately.
package docs

import (
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"sort"
	"strconv"
	"strings"

	contract "cyberguard/server"
)

//go:embed assets/swagger-ui.css
//go:embed assets/swagger-ui-bundle.js
//go:embed assets/swagger-ui-standalone-preset.js
//go:embed assets/favicon-16x16.png
//go:embed assets/favicon-32x32.png
//go:embed assets/VERSION
var assets embed.FS

// pageTitle is the browser title of the documentation page.
//
// It duplicates `info.title` in the contract, which is a real duplication. It
// is kept as a constant because extracting it would mean parsing the YAML on
// every page load or shipping a YAML parser to satisfy a browser tab label, and
// TestPageTitleMatchesTheContract fails if the two ever differ.
const pageTitle = "CyberGuard AI API"

// staticAsset is one servable file with its content type fixed.
//
// The types are literal rather than looked up because MIME resolution consults
// system tables, and a deployment's `/etc/mime.types` must not be able to change
// what this server claims it is sending.
type staticAsset struct {
	body        []byte
	contentType string
	etag        string
}

// permittedAssets is the complete set of files this package will serve.
//
// There is no directory index and no path resolution: a request is served only
// on an exact name match, so a traversal attempt is a 404 rather than something
// that has to be reasoned about.
var permittedAssets = map[string]string{
	"swagger-ui.css":                  "text/css; charset=utf-8",
	"swagger-ui-bundle.js":            "text/javascript; charset=utf-8",
	"swagger-ui-standalone-preset.js": "text/javascript; charset=utf-8",
	"favicon-16x16.png":               "image/png",
	"favicon-32x32.png":               "image/png",
}

// loaded holds the embedded assets, keyed by file name.
//
// It is populated once in init and only read afterwards, so it needs no lock.
var loaded map[string]staticAsset

// init loads the embedded assets.
//
// Failing here is deliberate. A missing or empty asset would otherwise produce
// a blank page for the user and one line in a log nobody reads; refusing to
// start makes the defect visible at boot instead.
func init() {
	loaded = make(map[string]staticAsset, len(permittedAssets))

	for name, contentType := range permittedAssets {
		body, err := assets.ReadFile("assets/" + name)
		if err != nil {
			panic(fmt.Sprintf("docs: vendored asset %q is missing: %v", name, err))
		}
		if len(body) == 0 {
			panic(fmt.Sprintf("docs: vendored asset %q is empty", name))
		}

		loaded[name] = staticAsset{
			body:        body,
			contentType: contentType,
			etag:        weakETag(body),
		}
	}
}

// Version returns the vendored Swagger UI release.
//
// It is surfaced on the served page, so an operator reading the page can tell
// which release their deployment runs — the first question asked when a
// documentation page misbehaves.
func Version() string {
	v, err := assets.ReadFile("assets/VERSION")
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(v))
}

// ------------------------------------------------------------------ assets

// AssetHandler serves the vendored static files.
//
// name is the request path after "/docs/assets/"; the router hands it over
// without a leading slash.
//
// notFound writes the response for an unrecognised name. It is supplied by the
// caller rather than hard-coded so that a miss is reported in this API's own
// error format — an RFC 9457 problem document — instead of the bare
// text/plain body Go's http.NotFound produces. One undocumented plain-text
// error shape among many problem documents is a trap for a client that parses
// errors uniformly.
func AssetHandler(name string, notFound func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		asset, ok := loaded[strings.TrimPrefix(name, "/")]
		if !ok {
			// No directory listing and no path resolution: this endpoint has
			// exactly the permitted names and nothing else.
			if notFound != nil {
				notFound(w, r)
				return
			}
			http.NotFound(w, r)
			return
		}

		// The assets are identified by content, so a strong validator is safe:
		// a client's cached copy is reused until the binary is upgraded, and a
		// rebuild of the same bytes produces the same tag.
		w.Header().Set("ETag", asset.etag)
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		w.Header().Set("Content-Type", asset.contentType)

		if matchETag(r, asset.etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(asset.body)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(asset.body)
	})
}

// -------------------------------------------------------------------- spec

// SpecHandler serves the authoritative OpenAPI document.
//
// It serves the embedded bytes, so what a client reads is exactly what is
// committed — not whatever happens to sit on the container's filesystem when the
// request arrives.
func SpecHandler() http.Handler {
	body := contract.OpenAPISpec
	etag := weakETag(body)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		// application/yaml is the registered media type for YAML (RFC 9512),
		// and it stops a browser from trying to render the document as a page.
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition",
			fmt.Sprintf("inline; filename=%q", contract.OpenAPISpecFilename))

		if matchETag(r, etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(body)))
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, bytes.NewReader(body))
	})
}

// -------------------------------------------------------------- the UI page

// indexTemplate is Swagger UI's documented bootstrap, reduced to what this
// service needs.
//
// Generated rather than shipped as a file so it cannot drift from the routes the
// server actually registers.
//
// Every URL is relative, and that is the important part. A page served from
// /docs/ resolves `assets/swagger-ui.css` to /docs/assets/swagger-ui.css and
// `../openapi.yaml` to /openapi.yaml, with no knowledge of the host it was
// served from. The documentation therefore works unchanged behind a reverse
// proxy, on another port, or under a path prefix — none of which an absolute URL
// would survive.
var indexTemplate = template.Must(template.New("docs").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{{.Title}}</title>
  <link rel="icon" type="image/png" sizes="32x32" href="{{.AssetBase}}favicon-32x32.png" />
  <link rel="icon" type="image/png" sizes="16x16" href="{{.AssetBase}}favicon-16x16.png" />
  <link rel="stylesheet" href="{{.AssetBase}}swagger-ui.css" />
  <style>
    body { margin: 0; background: #fafafa; }
    .cg-note { margin: 0; padding: 10px 20px; font: 13px/1.5 system-ui, sans-serif;
               color: #3b4151; background: #fff; border-bottom: 1px solid #e3e5e8; }
    .cg-note code { background: #f0f1f3; padding: 1px 5px; border-radius: 3px; }
  </style>
</head>
<body>
  <p class="cg-note">
    The live contract, served by this same process at <code>{{.SpecURL}}</code>.
    Requests from <em>Try it out</em> go to the server selected in the dropdown;
    the default is the documented local deployment. Swagger UI is vendored — no
    external network access is used to render this page.
  </p>
  <div id="swagger-ui"></div>

  <script src="{{.AssetBase}}swagger-ui-bundle.js" crossorigin="anonymous"></script>
  <script src="{{.AssetBase}}swagger-ui-standalone-preset.js" crossorigin="anonymous"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
        // Relative, so the page works behind any host, port or path prefix.
        url: "{{.SpecURL}}",
        dom_id: "#swagger-ui",
        layout: "StandaloneLayout",
        presets: [SwaggerUIBundle.presets.apis, SwaggerUIStandalonePreset],
        plugins: [SwaggerUIBundle.plugins.DownloadUrl],
        deepLinking: true,
        docExpansion: "list",
        defaultModelsExpandDepth: 1,
        displayRequestDuration: true,
        filter: true,
        tryItOutEnabled: true,
        // No authentication scheme is defined and there is nothing to send.
        // Persisting credentials for a service that has none is only a way to
        // leak them later.
        persistAuthorization: false,
        withCredentials: false
      });
    };
  </script>
</body>
</html>
`))

// UIHandler serves the Swagger UI page.
//
// The page is rendered once and reused: it is a constant for a given binary, and
// re-rendering per request would put a template execution on the request path
// for no benefit.
func UIHandler() http.Handler {
	var buf bytes.Buffer
	err := indexTemplate.Execute(&buf, struct {
		Title     string
		AssetBase string
		SpecURL   string
	}{Title: pageTitle, AssetBase: "assets/", SpecURL: "../openapi.yaml"})
	if err != nil {
		// The template is a constant with constant data, so this cannot vary
		// at runtime. A failure is a build defect, and must not degrade into a
		// blank page at request time.
		panic(fmt.Sprintf("docs: rendering the index page: %v", err))
	}
	page := buf.Bytes()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", weakETag(page))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// The page is same-origin with the API it documents and loads no
		// third-party script beyond the vendored bundle, so it needs no
		// cross-origin access and is granted none. It must not be cached by a
		// shared cache: it is generated per binary, not per user.
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Content-Security-Policy",
			"default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; "+
				"script-src 'self' 'unsafe-inline'; connect-src 'self'")

		if matchETag(r, w.Header().Get("ETag")) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(page)))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(page)
	})
}

// ------------------------------------------------------------------ helpers

// weakETag derives a strong entity tag from content.
//
// The digest is truncated: this is an HTTP change detector, not an integrity
// check, and 8 bytes is far beyond any realistic chance of collision for a
// handful of documents.
func weakETag(body []byte) string {
	sum := sha256.Sum256(body)
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

// matchETag reports whether the request already holds this representation.
func matchETag(r *http.Request, etag string) bool {
	header := strings.TrimSpace(r.Header.Get("If-None-Match"))
	if header == "" {
		return false
	}
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag || strings.TrimPrefix(candidate, "W/") == etag {
			return true
		}
	}
	return false
}

// AssetNames lists the servable asset names, sorted.
//
// It exists for tests, so the set of served files can be asserted without
// reaching into an unexported map.
func AssetNames() []string {
	out := make([]string, 0, len(permittedAssets))
	for name := range permittedAssets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// AssetFS exposes the embedded tree, for tests that need to read a file directly.
func AssetFS() fs.FS { return assets }

// PageTitle returns the title rendered on the documentation page.
func PageTitle() string { return pageTitle }
