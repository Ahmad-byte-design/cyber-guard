// Package apidocs embeds the OpenAPI contract so the served document is the
// committed document.
//
// The Go embed directive can only reach files inside the package directory,
// which is why the contract lives beside this file rather than somewhere else:
// the bytes served at /openapi.yaml are exactly docs/openapi.yaml in the
// repository, byte for byte, with no runtime file reads to misconfigure.
package apidocs

import _ "embed"

// OpenAPISpec is the raw YAML of the API contract.
//
//go:embed openapi.yaml
var OpenAPISpec []byte

// OpenAPISpecFilename is the file name reported in the Content-Disposition of
// the spec endpoint.
const OpenAPISpecFilename = "openapi.yaml"
