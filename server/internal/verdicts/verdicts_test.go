package verdicts

import "testing"

func TestAllVerdictsAreValid(t *testing.T) {
	t.Parallel()

	all := All()
	if len(all) != 5 {
		t.Fatalf("All() returned %d verdicts, want 5", len(all))
	}

	seen := make(map[Verdict]bool, len(all))
	for _, v := range all {
		if !v.Valid() {
			t.Errorf("%q reported invalid", v)
		}
		if seen[v] {
			t.Errorf("%q appears twice in All()", v)
		}
		seen[v] = true
		if v.String() != string(v) {
			t.Errorf("String() = %q, want %q", v.String(), v)
		}
	}
}

// The wire values are part of the API contract, so they are asserted literally.
func TestWireValuesAreStable(t *testing.T) {
	t.Parallel()

	want := map[Verdict]string{
		Malicious:        "malicious",
		Suspicious:       "suspicious",
		NoThreatDetected: "no_threat_detected",
		Inconclusive:     "inconclusive",
		Unknown:          "unknown",
	}

	for v, s := range want {
		if string(v) != s {
			t.Errorf("verdict wire value = %q, want %q", v, s)
		}
	}
}

// "benign" must never reappear: it reads as a safety guarantee.
func TestBenignIsNotAValidVerdict(t *testing.T) {
	t.Parallel()

	if Verdict("benign").Valid() {
		t.Error("benign is accepted as a verdict; ADR 0011 replaced it with no_threat_detected")
	}
}

func TestInvalidVerdictsAreRejected(t *testing.T) {
	t.Parallel()

	for _, v := range []Verdict{"", "safe", "clean", "MALICIOUS", "unknown "} {
		if v.Valid() {
			t.Errorf("%q reported valid", v)
		}
	}
}

func TestNormaliseLowerTrimsAndLowercases(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"  No Specific Threat  ": "no specific threat",
		"MALICIOUS":              "malicious",
		"\tSUSPICIOUS\n":         "suspicious",
		"":                       "",
		"   ":                    "",
	}

	for in, want := range cases {
		if got := NormaliseLower(in); got != want {
			t.Errorf("NormaliseLower(%q) = %q, want %q", in, got, want)
		}
	}
}
