// Package docs serves the OpenAPI contract and a Swagger UI for it, from the
// same binary that serves the API.
//
// # Why the assets are vendored
//
// Swagger UI is normally pulled from a CDN at page load. That is the wrong
// trade here: it makes the API contract unavailable exactly when it is most
// needed — an air-gapped deployment, an incident, a locked-down environment —
// and it makes the documentation's behaviour depend on a third party at
// runtime.
//
// So the distribution is vendored at a pinned version under assets/ and
// embedded into the binary with //go:embed. The pinned release is recorded in
// assets/VERSION, and assets/LICENSE is the upstream Apache-2.0 licence.
//
// # Why the asset list is an explicit map
//
// An embedded http.FileServer would be less code, but it also publishes a
// directory listing and serves whatever the embed happens to contain. Naming
// the permitted files means the surface is exactly what was reviewed, and a
// file dropped into assets/ by accident is not served until someone adds it
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
)

//go:embed assets/swagger-ui.css
//go:embed assets/swagger-ui-bundle.js
//go:embed assets/swagger-ui-standalone-preset.js
//go:embed assets/favicon-16x16.png
//go:embed assets/favicon-32x32.png
//go:embed assets/VERSION
var assets embed.FS

// pageTitle is the browser title of the documentation page.
const pageTitle = "CyberGuard AI API"

// staticAsset is one servable file with its content type fixed.
//
// The types are literal rather than looked up because MIME resolution consults
// system tables, and a deployment's /etc/mime.types must not be able to change
// what this server claims it is sending.
type staticAsset struct {
	body        []byte
	contentType string
	etag        string
}

// permittedAssets is the complete set of files this package will serve.
var permittedAssets = map[string]string{
	"swagger-ui.css":                  "text/css; charset=utf-8",
	"swagger-ui-bundle.js":            "text/javascript; charset=utf-8",
	"swagger-ui-standalone-preset.js": "text/javascript; charset=utf-8",
	"favicon-16x16.png":               "image/png",
	"favicon-32x32.png":               "image/png",
}

// loaded holds the embedded assets, keyed by file name. Populated once in
// init and only read afterwards, so it needs no lock.
var loaded map[string]staticAsset

// vendoredVersion is the Swagger UI release recorded in assets/VERSION.
var vendoredVersion string

// init loads the embedded assets, refusing to start on a missing or empty
// file: a blank documentation page is a defect nobody notices until they need
// the document, so it is made visible at boot instead.
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
		loaded[name] = staticAsset{body: body, contentType: contentType, etag: etagFor(body)}
	}

	raw, err := assets.ReadFile("assets/VERSION")
	if err != nil {
		panic(fmt.Sprintf("docs: the vendored version is missing: %v", err))
	}
	vendoredVersion = strings.TrimSpace(string(raw))
	if vendoredVersion == "" {
		panic("docs: assets/VERSION is empty")
	}
}

// Version returns the vendored Swagger UI release.
func Version() string { return vendoredVersion }

// ------------------------------------------------------------------ assets

// AssetHandler serves the vendored static files.
//
// name is the request path after "/docs/assets/". notFound writes the
// response for an unrecognised name; it is supplied by the caller so a miss
// is reported in this API's own JSON error format instead of Go's plain-text
// http.NotFound.
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

		// The assets are identified by content, so a strong validator is
		// safe: a client's cached copy is reused until the binary is
		// upgraded.
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
// spec is the embedded bytes from the apidocs package, so what a client reads
// is exactly what is committed — not whatever happens to sit on the
// container's filesystem when the request arrives.
func SpecHandler(spec []byte, filename string) http.Handler {
	etag := etagFor(spec)

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etag)
		// application/yaml is the registered media type for YAML (RFC 9512),
		// and it stops a browser trying to render the document as a page.
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Disposition", fmt.Sprintf("inline; filename=%q", filename))

		if matchETag(r, etag) {
			w.WriteHeader(http.StatusNotModified)
			return
		}

		w.Header().Set("Content-Length", strconv.Itoa(len(spec)))
		w.WriteHeader(http.StatusOK)
		_, _ = io.Copy(w, bytes.NewReader(spec))
	})
}

// -------------------------------------------------------------- the UI page

// indexTemplate is Swagger UI's documented bootstrap, reduced to what this
// service needs.
//
// Every URL is relative, and that is the important part. A page served from
// /docs/ resolves assets/swagger-ui.css to /docs/assets/swagger-ui.css and
// ../openapi.yaml to /openapi.yaml, with no knowledge of the host it was
// served from. The documentation therefore works unchanged behind a reverse
// proxy, on another port, or under a path prefix.
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
    <em>Try it out</em> sends requests to the server selected in the dropdown.
    Swagger UI {{.Version}} is vendored into this binary: no external network
    access is used to render this page.
  </p>
  <div id="swagger-ui"></div>

  <script src="{{.AssetBase}}swagger-ui-bundle.js" crossorigin="anonymous"></script>
  <script src="{{.AssetBase}}swagger-ui-standalone-preset.js" crossorigin="anonymous"></script>
  <script>
    window.onload = function () {
      window.ui = SwaggerUIBundle({
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
        // Persisting credentials for a service that has none is only a way
        // to leak them later.
        persistAuthorization: false,
        withCredentials: false
      });
    };
  </script>
</body>
</html>
`))

// UIHandler serves the Swagger UI page, rendered once per binary.
func UIHandler() http.Handler {
	var buf bytes.Buffer
	err := indexTemplate.Execute(&buf, struct {
		Title     string
		AssetBase string
		SpecURL   string
		Version   string
	}{
		Title:     pageTitle,
		AssetBase: "assets/",
		SpecURL:   "../openapi.yaml",
		Version:   Version(),
	})
	if err != nil {
		// The template is a constant with constant data, so this cannot vary
		// at runtime. A failure is a build defect, and must not degrade into
		// a blank page at request time.
		panic(fmt.Sprintf("docs: rendering the index page: %v", err))
	}
	page := buf.Bytes()

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", etagFor(page))
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		// Same-origin page, same-origin assets: it needs no cross-origin
		// access and is granted none.
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

// etagFor derives a strong entity tag from content.
func etagFor(body []byte) string {
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

// AssetNames lists the servable asset names, sorted. It exists for tests.
func AssetNames() []string {
	out := make([]string, 0, len(permittedAssets))
	for name := range permittedAssets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// AssetFS exposes the embedded tree, for tests that read a file directly.
func AssetFS() fs.FS { return assets }

// PageTitle returns the title rendered on the documentation page.
func PageTitle() string { return pageTitle }
