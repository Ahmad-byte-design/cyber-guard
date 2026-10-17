package urlintel

import (
	"strings"
	"testing"
)

func TestValidate(t *testing.T) {
	t.Parallel()

	valid := []string{
		"https://example.test/login",
		"http://example.test",
		"https://sub.example.test:8443/a/b?x=1&y=2",
		"  https://example.test/padded  ", // whitespace from paste is tolerated
		"https://example.test./trailing-dot",
	}
	for _, in := range valid {
		if _, err := Validate(in); err != nil {
			t.Errorf("Validate(%q) = %v, want nil", in, err)
		}
	}

	invalid := []string{
		"",                       // empty
		"   ",                    // whitespace only
		"not a url",              // no scheme
		"javascript:alert(1)",    // non-http scheme
		"file:///etc/passwd",     // non-http scheme
		"ftp://example.test",     // non-http scheme
		"https://",               // no host
		"https://user:pw@x.test", // embedded credentials
		"https://example.test:" + strings.Repeat("a", MaxURLLength), // overlong
		"https://exa\nmple.test",                                    // control character
	}
	for _, in := range invalid {
		if _, err := Validate(in); err == nil {
			t.Errorf("Validate(%q) = nil, want error", in)
		}
	}
}

func TestValidateRejectsOverlongInput(t *testing.T) {
	t.Parallel()
	long := "https://example.test/" + strings.Repeat("a", MaxURLLength)
	if _, err := Validate(long); !IsValidation(err) {
		t.Fatalf("overlong URL error = %v, want *ValidationError", err)
	}
}

func TestCanonical(t *testing.T) {
	t.Parallel()

	cases := []struct{ in, want string }{
		{"https://example.test", "https://example.test/"},
		{"https://EXAMPLE.TEST", "https://example.test/"},
		{"https://example.test/Path", "https://example.test/Path"},         // path case kept
		{"https://example.test/?B=2&a=1", "https://example.test/?B=2&a=1"}, // query order kept
		{"https://example.test/p#frag", "https://example.test/p"},          // fragment dropped
	}
	for _, c := range cases {
		u, err := Validate(c.in)
		if err != nil {
			t.Fatalf("Validate(%q): %v", c.in, err)
		}
		if got := Canonical(u); got != c.want {
			t.Errorf("Canonical(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// A URL differing only in case should fingerprint the same; one differing in
// path or query must not. Getting this backwards would either merge distinct
// assessments or silently miss cached hits.
func TestFingerprintSeparatesMeaningfulParts(t *testing.T) {
	t.Parallel()
	key := []byte("test-key")

	_, same, err := Prepare(key, "https://example.test/Login")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	_, upper, err := Prepare(key, "https://EXAMPLE.TEST/Login")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if same != upper {
		t.Errorf("host case changed fingerprint: %s vs %s", same, upper)
	}

	_, diffPath, err := Prepare(key, "https://example.test/login")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if same == diffPath {
		t.Error("different paths produced the same fingerprint")
	}

	_, diffQuery, err := Prepare(key, "https://example.test/Login?id=1")
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	if same == diffQuery {
		t.Error("different query produced the same fingerprint")
	}
}

func TestFingerprintIsStableAndKeyed(t *testing.T) {
	t.Parallel()

	a, err := Fingerprint([]byte("key-a"), "https://example.test/")
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	again, err := Fingerprint([]byte("key-a"), "https://example.test/")
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if a != again {
		t.Error("fingerprint is not deterministic")
	}

	b, err := Fingerprint([]byte("key-b"), "https://example.test/")
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if a == b {
		t.Error("fingerprint does not depend on the key")
	}

	if _, err := Fingerprint(nil, "https://example.test/"); err == nil {
		t.Error("empty key must be rejected")
	}
}
