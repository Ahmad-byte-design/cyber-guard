// Package server carries module-level artefacts that have to live at the module
// root.
//
// It exists for one reason: openapi.yaml must be embedded into the binary so
// that `GET /openapi.yaml` can serve it, but `//go:embed` cannot reach a parent
// directory. The specification therefore stays where the project already keeps
// it — `server/openapi.yaml`, beside the code it describes, reachable by
// `internal/httpapi`'s drift test without a Compose mount — and this package is
// the thin thing that embeds it.
//
// Embedding is what makes the served document trustworthy. A path read from
// disk at request time would serve whatever happened to be on that machine's
// filesystem, which is not necessarily the committed contract; a copy kept in
// sync by hand would drift. This way the bytes served are the bytes in the
// repository.
//
// There is no logic here and there should not be. The document is the artefact.
package server

import (
	_ "embed"
)

// OpenAPISpec is the authoritative OpenAPI document, byte for byte as committed.
//
// Exposed as a []byte rather than a string so a handler can hand it straight to
// an http.ResponseWriter without a conversion that could re-encode it.
//
//go:embed openapi.yaml
var OpenAPISpec []byte

// OpenAPISpecFilename is the name the document has on disk, used for the
// Content-Disposition a browser download would get.
const OpenAPISpecFilename = "openapi.yaml"
