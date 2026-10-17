package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

// POST /api/v1/get-url — the by-URL form of the scan lookup.
//
// The assertions here are mostly about what the endpoint must NOT do, because
// those are the properties that make it safe to expose: it must not create a
// scan, must not analyse anything, and must not let a URL escape into a log.

func lookupByURL(t *testing.T, h http.Handler, body string) *responseSnapshot {
	t.Helper()

	rec := do(t, h, http.MethodPost, "/api/v1/get-url", body, "application/json")

	out := &responseSnapshot{status: rec.Code, body: rec.Body.String()}
	_ = json.Unmarshal(rec.Body.Bytes(), &out.raw)
	return out
}

type responseSnapshot struct {
	status int
	body   string
	raw    map[string]any
}

func (r *responseSnapshot) code() string {
	c, _ := r.raw["code"].(string)
	return c
}

// A URL that was never scanned has no answer, and the code must be the same one
// a lookup by an unknown scan ID returns.
func TestGetURLByURLReturnsNotFoundForAnUnscannedURL(t *testing.T) {
	t.Parallel()

	got := lookupByURL(t, docsServer(t, true), `{"url":"https://never-scanned.example.test/x"}`)

	if got.status != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", got.status)
	}
	if got.code() != "scan_not_found" {
		t.Errorf("code = %q, want scan_not_found", got.code())
	}
}

// The 400/422 split is deliberate and must match check-url exactly.
//
// 400 means the body itself was unusable: not JSON, or not an object with a
// `url` field. 422 means the body was well-formed and the *value* was
// unacceptable — an empty `url` is a value problem, not a syntax problem.
func TestGetURLByURLRejectsAMalformedBody(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	cases := []struct {
		name string
		body string
		want int
		code string
	}{
		{"empty body", ``, http.StatusBadRequest, "invalid_request"},
		{"not json", `not json`, http.StatusBadRequest, "invalid_request"},
		{"wrong field name", `{"uri":"https://x.test"}`, http.StatusBadRequest, "invalid_request"},
		{"array not object", `["https://x.test"]`, http.StatusBadRequest, "invalid_request"},
		{"missing url", `{}`, http.StatusUnprocessableEntity, "validation_error"},
		{"empty url", `{"url":""}`, http.StatusUnprocessableEntity, "validation_error"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lookupByURL(t, h, tc.body)
			if got.status != tc.want {
				t.Errorf("body %q -> status %d, want %d", tc.body, got.status, tc.want)
			}
			if got.code() != tc.code {
				t.Errorf("body %q -> code %q, want %q", tc.body, got.code(), tc.code)
			}
		})
	}
}

// Validation must match check-url exactly, or a client that submits and then
// polls by URL sees a different answer for the same input.
func TestGetURLByURLValidatesLikeCheckURL(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	cases := []struct {
		name string
		url  string
		want int
	}{
		{"unsupported scheme", "ftp://example.test/x", http.StatusUnprocessableEntity},
		{"no scheme", "example.test/x", http.StatusUnprocessableEntity},
		{"no hostname", "https:///x", http.StatusUnprocessableEntity},
		{"loopback", "http://127.0.0.1/x", http.StatusUnprocessableEntity},
		{"private range", "https://10.0.0.1/x", http.StatusUnprocessableEntity},
		{"link local", "https://169.254.169.254/latest/meta-data", http.StatusUnprocessableEntity},
		{"single label", "https://intranet/x", http.StatusUnprocessableEntity},
		{"embedded credentials", "https://user:pass@example.test/x", http.StatusUnprocessableEntity},
		{"too long", "https://example.test/" + strings.Repeat("a", 2100), http.StatusUnprocessableEntity},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := lookupByURL(t, h, `{"url":`+mustJSON(tc.url)+`}`)
			if got.status != tc.want {
				t.Errorf("%s: status = %d, want %d", tc.name, got.status, tc.want)
			}
			if tc.want == http.StatusUnprocessableEntity && got.code() != "validation_error" {
				t.Errorf("%s: code = %q, want validation_error", tc.name, got.code())
			}
		})
	}
}

// A reserved documentation name is analysable, so a lookup must accept it.
// Every example in this project's own contract uses one; a lookup that refused
// them would make the documented examples unusable.
func TestGetURLByURLAcceptsReservedDocumentationNames(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	for _, url := range []string{
		"https://example.test/login",
		"https://example.example/login",
		"https://example.invalid/login",
	} {
		got := lookupByURL(t, h, `{"url":`+mustJSON(url)+`}`)
		// 404, not 422: accepted, just never scanned.
		if got.status != http.StatusNotFound {
			t.Errorf("%s: status = %d, want 404 (accepted but unscanned)", url, got.status)
		}
	}
}

// The endpoint must not create a scan. A lookup that could trigger analysis
// would be a second submission endpoint with a different name and no separate
// quota accounting.
func TestGetURLByURLNeverCreatesAScan(t *testing.T) {
	t.Parallel()

	rig := newDocsRig(t)
	h := rig.handler
	before := rig.serviceStore().ScanCount()

	for i := range 5 {
		lookupByURL(t, h, `{"url":"https://`+string(rune('a'+i))+`.example.test/x"}`)
	}

	if after := rig.serviceStore().ScanCount(); after != before {
		t.Errorf("scan count went from %d to %d; a lookup must not create scans", before, after)
	}
}

// Nothing about the URL may be echoed anywhere in the response. The response is
// the one place a client is certain to look, and the URL is not theirs to read
// back from us.
func TestGetURLByURLNeverEchoesTheURL(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	const secret = "https://secret-path.example.test/private/token"
	for _, body := range []string{
		`{"url":` + mustJSON(secret) + `}`,
		`{"url":` + mustJSON("ftp://"+secret) + `}`,
		`{"url":` + mustJSON("https://user:pass@"+"example.test/x") + `}`,
		`{"url":` + mustJSON("http://127.0.0.1/admin") + `}`,
	} {
		got := lookupByURL(t, h, body)
		for _, leak := range []string{"secret-path", "token", "user:pass", "127.0.0.1", "admin"} {
			if strings.Contains(got.body, leak) {
				t.Errorf("the response echoes %q: %s", leak, got.body)
			}
		}
	}
}

// The response for an unknown URL must be indistinguishable from the response
// for an unknown scan ID, so the endpoint cannot be used to test which URLs
// have been scanned by comparing shapes.
func TestGetURLByURLAndByIDAgreeOnNotFound(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	byURL := lookupByURL(t, h, `{"url":"https://nothing.example.test/x"}`)
	byID := do(t, h, http.MethodGet, "/api/v1/get-url/scan_absent", "", "")

	if byURL.status != byID.Code {
		t.Errorf("status by url = %d, by id = %d", byURL.status, byID.Code)
	}

	var fromID problem
	_ = json.Unmarshal(byID.Body.Bytes(), &fromID)
	if byURL.code() != fromID.Code {
		t.Errorf("code by url = %q, by id = %q", byURL.code(), fromID.Code)
	}
}

// A body that is too large must be refused by the same limit as check-url, not
// read into memory.
func TestGetURLByURLEnforcesTheBodySizeLimit(t *testing.T) {
	t.Parallel()

	h := docsServer(t, true)

	huge := `{"url":"https://example.test/` + strings.Repeat("a", 32*1024) + `"}`
	got := lookupByURL(t, h, huge)

	if got.status != http.StatusBadRequest && got.status != http.StatusUnprocessableEntity {
		t.Errorf("a %d-byte body returned %d, want 400 or 422", len(huge), got.status)
	}
}

// mustJSON encodes a Go string as a JSON string literal.
func mustJSON(s string) string {
	b, err := json.Marshal(s)
	if err != nil {
		panic(err)
	}
	return string(b)
}
