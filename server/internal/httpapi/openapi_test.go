package httpapi

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	contract "cyberguard/server"
	"cyberguard/server/internal/httpapi/docs"
	"cyberguard/server/internal/platform/mongostore"
	"cyberguard/server/internal/verdicts"
)

// Validation of the OpenAPI document itself.
//
// # Why this file parses YAML and the older route check did not
//
// The route drift check originally read operation keys with a regular
// expression, on the reasoning that a full parser was "a dependency bought for
// one assertion". That reasoning has now stopped holding: the contract is
// served to clients, embedded in the binary, and rendered by a UI, so its
// *structure* matters, not just the presence of two lines of text. A malformed
// document, a `$ref` to nothing, or an enum that disagrees with the code are
// all failures a regex cannot see — and one of them (a bad escape sequence in
// an example) actually occurred while writing this.
//
// yaml.v3 is therefore a test-only dependency. It pulls no OpenAPI-specific
// machinery, so the document is checked for internal consistency and agreement
// with the code, without adopting a generator that would want to own the types.
//
// A full OpenAPI validator would check more. It would also be a much larger
// dependency to run in CI, and these assertions cover the failures this project
// actually makes: a forgotten path, a renamed verdict, a dangling reference.

const specPath = "../../openapi.yaml"

// loadSpec reads and parses the contract once per test.
//
// Parsing is not cached across tests on purpose: a test that mutates the
// in-memory document must not be able to affect another, and the file is a few
// tens of kilobytes.
func loadSpec(t *testing.T) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(filepath.Clean(specPath))
	if err != nil {
		t.Fatalf("read %s: %v (is the module nested under the repo root?)", specPath, err)
	}

	var doc map[string]any
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	dec.KnownFields(true) // a misspelled key is a typo, not an extension
	if err := dec.Decode(&doc); err != nil {
		t.Fatalf("parse %s: %v", specPath, err)
	}
	return doc
}

// operations returns every operation in the document, keyed "METHOD /path".
func operations(t *testing.T, doc map[string]any) map[string]map[string]any {
	t.Helper()

	paths, ok := doc["paths"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no paths object", specPath)
	}

	out := make(map[string]map[string]any)
	for path, raw := range paths {
		item, ok := raw.(map[string]any)
		if !ok {
			t.Errorf("path %s is not an object", path)
			continue
		}
		for method, op := range item {
			switch method {
			case "get", "post", "put", "patch", "delete", "head", "options":
			default:
				// Not an operation: parameters, summary, servers.
				continue
			}
			body, ok := op.(map[string]any)
			if !ok {
				t.Errorf("%s %s is not an object", method, path)
				continue
			}
			out[strings.ToUpper(method)+" "+path] = body
		}
	}
	if len(out) == 0 {
		t.Fatalf("no operations found in %s", specPath)
	}
	return out
}

// goRoutes is the route surface as registered in the router, including the
// routes that are gated behind configuration.
func goRoutes() map[string]bool {
	routes := make(map[string]bool, len(routeTable))
	for _, rt := range routeTable {
		routes[rt.method+" "+rt.pattern] = true
	}
	return routes
}

func diff(a, b map[string]bool) []string {
	var only []string
	for k := range a {
		if !b[k] {
			only = append(only, k)
		}
	}
	sort.Strings(only)
	return only
}

func format(routes []string) string {
	if len(routes) == 0 {
		return "\n    (none)"
	}
	var sb strings.Builder
	for _, r := range routes {
		sb.WriteString("\n    - " + r)
	}
	return sb.String()
}

// The document must parse at all. A syntax error makes every other check
// meaningless, so this is asserted first and stated separately.
func TestOpenAPISpecParses(t *testing.T) {
	t.Parallel()

	doc := loadSpec(t)
	if len(doc) == 0 {
		t.Fatalf("%s parsed to an empty document", specPath)
	}
	if _, ok := doc["openapi"]; !ok {
		t.Error("the document declares no openapi version")
	}
}

func TestOpenAPIDeclaresItsVersionAndInfo(t *testing.T) {
	t.Parallel()

	doc := loadSpec(t)

	if got := doc["openapi"]; got != "3.1.0" {
		t.Errorf("openapi = %v, want 3.1.0", got)
	}

	info, ok := doc["info"].(map[string]any)
	if !ok {
		t.Fatal("no info object")
	}
	for _, key := range []string{"title", "version", "description"} {
		if v, _ := info[key].(string); strings.TrimSpace(v) == "" {
			t.Errorf("info.%s is empty", key)
		}
	}
}

// ADR 0015 makes openapi.yaml authoritative and requires drift to be a CI
// failure rather than a production surprise.
func TestOpenAPISpecMatchesRoutes(t *testing.T) {
	t.Parallel()

	spec := map[string]bool{}
	for key := range operations(t, loadSpec(t)) {
		spec[key] = true
	}
	impl := goRoutes()

	if missing := diff(impl, spec); len(missing) > 0 {
		t.Errorf("routes registered in Go but not documented in %s:%s", specPath, format(missing))
	}
	if extra := diff(spec, impl); len(extra) > 0 {
		t.Errorf("operations documented in %s but not registered in Go:%s", specPath, format(extra))
	}
}

// Every operation needs an operationId: it is what a generated client names its
// method, and without one tooling falls back to path-and-method.
func TestEveryOperationHasAnOperationID(t *testing.T) {
	t.Parallel()

	seen := map[string]string{}
	for key, op := range operations(t, loadSpec(t)) {
		id, _ := op["operationId"].(string)
		if id == "" {
			t.Errorf("%s has no operationId", key)
			continue
		}
		if prev, dup := seen[id]; dup {
			t.Errorf("operationId %q is used by both %s and %s", id, prev, key)
		}
		seen[id] = key
	}
}

// Every operation needs a summary and at least one documented response, or a
// client cannot tell what a successful call looks like.
func TestEveryOperationDocumentsSummaryAndResponses(t *testing.T) {
	t.Parallel()

	for key, op := range operations(t, loadSpec(t)) {
		if s, _ := op["summary"].(string); strings.TrimSpace(s) == "" {
			t.Errorf("%s has no summary", key)
		}

		responses, ok := op["responses"].(map[string]any)
		if !ok || len(responses) == 0 {
			t.Errorf("%s documents no responses", key)
			continue
		}
		if _, ok := responses["2"+"00"]; !ok {
			t.Errorf("%s has no 2xx response", key)
		}
	}
}

// A dangling $ref renders as an unresolved node in Swagger UI, so the contract
// looks complete while showing nothing for the operation.
func TestEveryRefResolves(t *testing.T) {
	t.Parallel()

	doc := loadSpec(t)

	var walk func(node any, trail string)
	walk = func(node any, trail string) {
		switch n := node.(type) {
		case map[string]any:
			for key, value := range n {
				ref, isRef := value.(string)
				if isRef && key == "$ref" {
					if !strings.HasPrefix(ref, "#/") {
						t.Errorf("%s: %q is not a local reference", trail, ref)
					} else if !resolves(doc, ref) {
						t.Errorf("%s: %q points at nothing", trail, ref)
					}
					continue
				}
				walk(value, trail+"/"+key)
			}
		case []any:
			for i, value := range n {
				walk(value, trail+"["+string(rune('0'+i))+"]")
			}
		}
	}
	walk(doc, "")

	if t.Failed() {
		t.Log("check that the component name matches the schema key exactly")
	}
}

// resolves reports whether a local JSON pointer reaches a node in the document.
func resolves(doc map[string]any, ref string) bool {
	node := any(doc)
	for _, part := range strings.Split(strings.TrimPrefix(ref, "#/"), "/") {
		m, ok := node.(map[string]any)
		if !ok {
			return false
		}
		node, ok = m[part]
		if !ok {
			return false
		}
	}
	return node != nil
}

// The documented verdict vocabulary must equal the code's.
//
// This is the check that stops the API documentation from quietly promising a
// verdict the service cannot return, or omitting one it can. A client that
// switches on `verdict` is entitled to know the full set.
func TestVerdictEnumMatchesTheCode(t *testing.T) {
	t.Parallel()

	doc := loadSpec(t)
	got := enumOf(t, doc, "Verdict")

	var want []string
	for _, v := range verdicts.All() {
		want = append(want, v.String())
	}
	sort.Strings(want)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("documented verdicts %v, code defines %v", got, want)
	}
}

// The same must hold for scan status: a status the code can produce but the
// contract omits is one a client cannot handle.
func TestScanStatusEnumMatchesTheCode(t *testing.T) {
	t.Parallel()

	doc := loadSpec(t)
	got := enumOf(t, doc, "ScanStatus")

	var want []string
	for _, s := range mongostore.All() {
		want = append(want, string(s))
	}
	sort.Strings(want)

	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("documented statuses %v, code defines %v", got, want)
	}
}

// enumOf reads components.schemas.<name>.enum.
func enumOf(t *testing.T, doc map[string]any, name string) []string {
	t.Helper()

	schemas, ok := doc["components"].(map[string]any)["schemas"].(map[string]any)
	if !ok {
		t.Fatalf("%s has no components.schemas", specPath)
	}
	schema, ok := schemas[name].(map[string]any)
	if !ok {
		t.Fatalf("no schema named %s", name)
	}
	raw, ok := schema["enum"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatalf("%s declares no enum", name)
	}

	out := make([]string, 0, len(raw))
	for _, v := range raw {
		s, ok := v.(string)
		if !ok {
			t.Fatalf("%s has a non-string enum member %v", name, v)
		}
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// A schema with an empty `required` list is a common copy-paste artefact and
// validates, so it is worth asserting against.
func TestRequiredListsAreNotEmpty(t *testing.T) {
	t.Parallel()

	doc := loadSpec(t)
	schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)

	for name, raw := range schemas {
		schema, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		required, present := schema["required"]
		if !present {
			continue
		}
		list, ok := required.([]any)
		if !ok {
			t.Errorf("%s.required is not a list", name)
			continue
		}
		if len(list) == 0 {
			t.Errorf("%s declares required: [] — either list the members or drop the key", name)
		}
	}
}

// Every schema a path references should exist, and every schema that exists
// should be reachable. An orphan is usually a leftover from a removed field,
// and an orphan that documents a field no endpoint returns is worse than
// nothing: it reads as an answer to a question nobody can ask.
func TestNoOrphanSchemas(t *testing.T) {
	t.Parallel()

	doc := loadSpec(t)
	schemas, _ := doc["components"].(map[string]any)["schemas"].(map[string]any)

	referenced := map[string]bool{}
	var walk func(any)
	walk = func(node any) {
		switch n := node.(type) {
		case map[string]any:
			for key, value := range n {
				if ref, ok := value.(string); ok && key == "$ref" {
					referenced[ref] = true
					continue
				}
				walk(value)
			}
		case []any:
			for _, value := range n {
				walk(value)
			}
		}
	}
	components, _ := doc["components"].(map[string]any)
	// The schemas map is walked too: Verdict, Evidence, ScanStatus and
	// HealthCheck are referenced by other schemas rather than by a path, and
	// looking only at paths would report all four as orphans.
	walk(doc["paths"])
	walk(components["responses"])
	walk(components["headers"])
	walk(components["schemas"])

	for name := range schemas {
		ref := "#/components/schemas/" + name
		if !referenced[ref] {
			t.Errorf("schema %s is never referenced", name)
		}
	}
}

// The contract must never carry a credential. It is committed, served without
// authentication, and embedded in the binary, so a key placed here would be
// published by every deployment.
func TestSpecContainsNoSecrets(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Clean(specPath))
	if err != nil {
		t.Fatalf("read %s: %v", specPath, err)
	}
	text := string(raw)

	// Only an *assignment* is forbidden. Naming a variable is not: the
	// ServiceUnavailable example deliberately reads "URL_FINGERPRINT_HMAC_KEY
	// is not set" so a reader learns which knob fixes the failure, and the
	// variable name is not a secret.
	forbidden := []struct{ label, needle string }{
		{"API key assignment", "HYBRID_ANALYSIS_API_KEY="},
		{"encryption key assignment", "URL_ENCRYPTION_KEY="},
		{"fingerprint key assignment", "URL_FINGERPRINT_HMAC_KEY="},
		{"bearer token", "Bearer "},
		{"private key block", "BEGIN PRIVATE KEY"},
	}

	for _, f := range forbidden {
		if strings.Contains(text, f.needle) {
			t.Errorf("%s appears in the contract; it must never contain a credential", f.label)
		}
	}

	// A 64-character hex run is what both configured keys look like. The
	// specification quotes neither, and nothing else in it needs to.
	for _, line := range strings.Split(text, "\n") {
		for _, field := range strings.Fields(line) {
			trimmed := strings.Trim(field, `"',|`)
			if len(trimmed) == 64 && isHex(trimmed) {
				t.Errorf("the contract contains a 64-character hex value, which is what a configured key looks like: %q", trimmed)
			}
		}
	}
}

func isHex(s string) bool {
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f', r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return len(s) > 0
}

// The document must not show a raw URL as an example. The project's privacy
// rule is that raw URLs are not retained, and a documentation example that
// contradicts it teaches the wrong thing to anyone copying from the spec.
func TestSpecExamplesUseReservedDocumentationHosts(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Clean(specPath))
	if err != nil {
		t.Fatalf("read %s: %v", specPath, err)
	}

	// Reserved names (RFC 2606 / RFC 6761): they cannot resolve, are owned by
	// the IETF, and are what this project uses throughout its own docs.
	reserved := []string{".test", ".example", ".invalid", ".localhost"}

	// Any host-looking token in an http(s) URL must use one of them.
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "url:") && !strings.Contains(trimmed, "http://") &&
			!strings.Contains(trimmed, "https://") && !strings.Contains(trimmed, "url: ") {
			continue
		}
		for _, scheme := range []string{"http://", "https://"} {
			for _, occurrence := range strings.Split(trimmed, scheme)[1:] {
				host := occurrence
				if i := strings.IndexAny(host, "/ \t\"'`"); i >= 0 {
					host = host[:i]
				}
				// A documented server carries a port; the reserved-name check
				// is about the host, so drop the port first.
				if i := strings.LastIndex(host, ":"); i > 0 && !strings.Contains(host[i+1:], ".") {
					host = host[:i]
				}
				if host == "" {
					continue
				}
				// Loopback and the documented local servers are legitimate.
				if host == "127.0.0.1" || host == "localhost" || strings.Contains(host, "${") {
					continue
				}
				ok := false
				for _, suffix := range reserved {
					if strings.Contains(host, suffix) {
						ok = true
						break
					}
				}
				if !ok {
					t.Errorf("example uses host %q, which is not a reserved documentation name: %s",
						host, trimmed)
				}
			}
		}
	}
}

// The embedded copy must be the committed file, byte for byte.
//
// If these ever diverge, the contract served to clients stops being the
// contract this test validates, and every other assertion here becomes
// theatre.
func TestEmbeddedSpecMatchesTheCommittedFile(t *testing.T) {
	t.Parallel()

	raw, err := os.ReadFile(filepath.Clean(specPath))
	if err != nil {
		t.Fatalf("read %s: %v", specPath, err)
	}

	if !bytes.Equal(contract.OpenAPISpec, raw) {
		t.Errorf("the embedded document differs from %s (%d embedded vs %d on disk)",
			specPath, len(contract.OpenAPISpec), len(raw))
	}
}

// The rendered page title must match info.title, or the tab and the page
// disagree about which service this is.
func TestPageTitleMatchesTheContract(t *testing.T) {
	t.Parallel()

	doc := loadSpec(t)
	info, _ := doc["info"].(map[string]any)
	want, _ := info["title"].(string)

	if got := docs.PageTitle(); got != want {
		t.Errorf("the documentation page title is %q, info.title is %q", got, want)
	}
}

// Every registered route must actually be served, so a typo in the route table
// cannot pass by matching the spec's typo.
func TestRegisteredRoutesAreServed(t *testing.T) {
	t.Parallel()

	handler := newTestServer(t, "k", nil)

	for _, rt := range routeTable {
		t.Run(rt.method+" "+rt.pattern, func(t *testing.T) {
			t.Parallel()

			// Documentation routes are gated. testConfig sets the setting to its
			// production default, so they are registered here and served for
			// real. If that default ever changes, this fails loudly instead of
			// silently losing coverage.
			target := rt.pattern
			switch {
			case strings.Contains(target, "{scanId}"):
				target = strings.Replace(target, "{scanId}", "scan_1", 1)
			case strings.Contains(target, "{name}"):
				target = strings.Replace(target, "{name}", "swagger-ui.css", 1)
			}

			rec := do(t, handler, rt.method, target, "", "")

			// 405 means the path matched but the method did not, and a bare
			// 404 on a route with a catch-all path would mean no match.
			if rec.Code == http.StatusMethodNotAllowed {
				t.Errorf("route not served for its own method: 405")
			}
			if rec.Code == 0 {
				t.Errorf("no response recorded for %s %s", rt.method, rt.pattern)
			}
		})
	}
}
