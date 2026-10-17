package httpapi

import (
	"net/http"

	"cyberguard/server/internal/httpapi/docs"
)

// Documentation endpoints.
//
// Swagger UI and the raw contract are served by the same binary as the API, for
// three reasons: a client can always discover the contract from the service it
// is talking to; the served bytes are the committed bytes, embedded at build
// time, so a deployment cannot serve a contract that disagrees with its code;
// and nothing has to be installed to read either.
//
// Neither endpoint touches a datastore or the queue. They are static content, so
// they work when the rest of the service is degraded — which is when an operator
// most wants to read the contract.

func (s *Server) handleDocsUI(w http.ResponseWriter, r *http.Request) {
	docs.UIHandler().ServeHTTP(w, r)
}

func (s *Server) handleOpenAPISpec(w http.ResponseWriter, r *http.Request) {
	docs.SpecHandler().ServeHTTP(w, r)
}

func (s *Server) handleDocsAsset(w http.ResponseWriter, r *http.Request) {
	docs.AssetHandler(r.PathValue("name"), func(w http.ResponseWriter, r *http.Request) {
		// Reported in the API's own error format rather than Go's default
		// plain text, so every error this service emits is RFC 9457.
		writeError(w, r, http.StatusNotFound, "not_found",
			"no such documentation asset")
	}).ServeHTTP(w, r)
}
