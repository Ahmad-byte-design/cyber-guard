package services

// Tests for the documented verdict normalization policy (verdict.go).
//
// The cases below pin every rule the documentation states: malicious and
// suspicious outrank clean, only unanimously completed benign evidence
// supports no_threat_detected, missing scanners are never clean evidence, a
// finished scan with unresolved or errored scanners is inconclusive, nothing
// usable is unknown, provider errors never become verdicts, and an unfinished
// scan is never judged.

import (
	"testing"

	"cyberguard/internal/hybridanalysis"
	"cyberguard/internal/models"
)

// scannersV2 builds a scanners_v2 object whose entries carry the given
// statuses, after the real provider's wire shape.
func scannersV2(statuses map[string]string) map[string]any {
	out := make(map[string]any, len(statuses))
	for name, status := range statuses {
		out[name] = map[string]any{"status": status, "progress": 100}
	}
	return out
}

func verdictResult(finished bool, v2 map[string]any) hybridanalysis.Result {
	return hybridanalysis.Result{
		ID: "qs-v", Finished: finished,
		ScannersV2: v2,
	}
}

func TestVerdictNormalization(t *testing.T) {
	cases := []struct {
		name     string
		finished bool
		v2       map[string]any
		scanners []models.Scanner
		want     string // empty means: verdict must stay null
	}{
		{
			// Rule 1: confirmed malicious wins over everything.
			"malicious outright",
			true,
			scannersV2(map[string]string{"clean_dns": "clean", "bfore_ai": "malicious"}),
			nil,
			models.VerdictMalicious,
		},
		{
			// Conflicting malicious and clean evidence: worst is preserved.
			"malicious beats clean",
			true,
			scannersV2(map[string]string{"a": "clean", "b": "clean", "c": "malicious"}),
			nil,
			models.VerdictMalicious,
		},
		{
			// Rule 2: suspicious outranks clean.
			"suspicious beats clean",
			true,
			scannersV2(map[string]string{"a": "clean", "b": "suspicious", "c": "clean"}),
			nil,
			models.VerdictSuspicious,
		},
		{
			"highest reported threat class wins",
			true,
			scannersV2(map[string]string{"a": "suspicious", "b": "malicious"}),
			nil,
			models.VerdictMalicious,
		},
		{
			// Rule 3: all evaluated scanners benign.
			"all clean",
			true,
			scannersV2(map[string]string{"a": "clean", "b": "clean"}),
			nil,
			models.VerdictNoThreat,
		},
		{
			"no specific threat counts as benign",
			true,
			nil,
			[]models.Scanner{{Name: "metadefender", Status: "no specific threat", StatusRaw: "NO_DETECTION"}},
			models.VerdictNoThreat,
		},
		{
			// "whitelisted" is the vendor's benign status.
			"whitelisted counts as benign",
			true,
			scannersV2(map[string]string{"a": "whitelisted"}),
			nil,
			models.VerdictNoThreat,
		},
		{
			// Missing scanners are not clean: the null (unconfigured or
			// unpopulated) entries contribute nothing, so the verdict rests
			// on the entries that actually produced data — and only when
			// those are unanimous benign.
			"missing entries are ignored, present ones decide",
			true,
			map[string]any{
				"a":            map[string]any{"status": "clean", "progress": 100},
				"b":            map[string]any{"status": "clean", "progress": 100},
				"virustotal":   nil,
				"metadefender": nil,
			},
			nil,
			models.VerdictNoThreat,
		},
		{
			// Rule 4: unresolved evidence is inconclusive.
			"no-classification is unresolved",
			true,
			scannersV2(map[string]string{"urlscan_io": "no-classification", "a": "clean"}),
			nil,
			models.VerdictInconclusive,
		},
		{
			"in-queue is unresolved",
			true,
			scannersV2(map[string]string{"vipre": "in-queue", "a": "clean"}),
			nil,
			models.VerdictInconclusive,
		},
		{
			// A failed scanner never reads as safe.
			"errored scanner is inconclusive",
			true,
			scannersV2(map[string]string{"a": "clean", "b": "error"}),
			nil,
			models.VerdictInconclusive,
		},
		{
			"error_message makes an unclassified entry failed",
			true,
			map[string]any{"a": map[string]any{"status": "something odd", "error_message": "scanner unavailable"}},
			nil,
			models.VerdictInconclusive,
		},
		{
			// Rule 5: finished but nothing was evaluated.
			"all entries missing is unknown",
			true,
			map[string]any{"virustotal": nil, "metadefender": nil},
			nil,
			models.VerdictUnknown,
		},
		{
			"no scanner data at all is unknown",
			true,
			nil,
			nil,
			models.VerdictUnknown,
		},
		{
			// An entry that carries no verdict fields is unresolved, and
			// unfinished responses are never judged.
			"fieldless entry is unresolved",
			true,
			map[string]any{"crowdstrike_ml": map[string]any{"progress": 100}},
			nil,
			models.VerdictInconclusive,
		},
		{
			"non-object entry is missing",
			true,
			map[string]any{"virustotal": 3},
			nil,
			models.VerdictUnknown,
		},
		{
			// The immutable rule: an unfinished scan has no verdict.
			"unfinished is never judged, even with malicious evidence",
			false,
			scannersV2(map[string]string{"a": "malicious"}),
			nil,
			"",
		},
		{
			// Unrecognised status text must not become a clean verdict.
			"unknown status text never counts as clean",
			true,
			scannersV2(map[string]string{"a": "SIGMA RANK 2024"}),
			nil,
			models.VerdictInconclusive,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := verdictResult(tc.finished, tc.v2)
			if tc.scanners != nil {
				r.Scanners = tc.scanners
			}

			verdict, ok := normalizeVerdict(r)
			if tc.want == "" {
				if ok {
					t.Fatalf("normalizeVerdict = %q, want no verdict", verdict)
				}
				return
			}
			if !ok {
				t.Fatalf("normalizeVerdict reported no verdict, want %q", tc.want)
			}
			if verdict != tc.want {
				t.Errorf("normalizeVerdict = %q, want %q", verdict, tc.want)
			}
		})
	}
}

func TestVerdictNeverFabricatedFromHashAlone(t *testing.T) {
	// A SHA-256 without scanner evidence is not a verdict of any kind.
	r := hybridanalysis.Result{
		ID: "qs-h", Finished: true, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	}
	verdict, ok := normalizeVerdict(r)
	if verdict != models.VerdictUnknown || !ok {
		t.Errorf("normalizeVerdict = (%q, %v), want unknown", verdict, ok)
	}
}
