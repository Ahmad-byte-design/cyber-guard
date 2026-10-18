package handlers

import (
	"net/http"
	"strings"

	apidocs "cyberguard/docs"
	"cyberguard/internal/docs"
)

// Documentation endpoints.
//
// Swagger UI and the raw contract are served by the same binary as the API,
// for three reasons: a client can always discover the contract from the
// service it is talking to; the served bytes are the committed bytes, embedded
// at build time, so a deployment cannot serve a contract that disagrees with
// its code; and nothing has to be installed to read either.
//
// Neither endpoint touches MongoDB or the provider. They are static content,
// so they work when the rest of the service is degraded — which is when an
// operator most wants to read the contract.

// handleOpenAPISpec serves the embedded contract at GET /openapi.yaml.
func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	if !checkMethod(w, r, http.MethodGet, http.MethodHead) {
		return
	}
	docs.SpecHandler(apidocs.OpenAPISpec, apidocs.OpenAPISpecFilename).ServeHTTP(w, r)
}

// handleDocs serves the Swagger UI page and its vendored assets under the
// /docs/ subtree.
func (s *Server) handleDocs(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/docs/" || r.URL.Path == "/docs":
		if !checkMethod(w, r, http.MethodGet) {
			return
		}
		docs.UIHandler().ServeHTTP(w, r)

	case strings.HasPrefix(r.URL.Path, "/docs/assets/"):
		if !checkMethod(w, r, http.MethodGet) {
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/docs/assets/")
		docs.AssetHandler(name, func(w http.ResponseWriter, r *http.Request) {
			// Reported in the API's own error format rather than Go's
			// default plain text, so every error this service emits is the
			// same JSON shape.
			writeError(w, r, http.StatusNotFound, "not_found",
				"no such documentation asset")
		}).ServeHTTP(w, r)

	default:
		writeError(w, r, http.StatusNotFound, "not_found",
			"no endpoint matches this method and path")
	}
}
