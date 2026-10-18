package services

// Verdict normalization.
//
// The provider's Quick Scan schema documents no aggregate verdict field; it
// returns per-scanner status strings ("Quick Scan status presented at the UI",
// optionally with a raw variant) and a nullable error message per scanner.
// This file is the single function that maps such evidence onto the
// application verdict vocabulary — malicious, suspicious, no_threat_detected,
// inconclusive, unknown — without ever inventing a safe answer.
//
// Extraction rules:
//
//   - Only `finished: true` responses are normalized. A pending scan has no
//     verdict; the caller stores and returns null instead.
//   - Every scanner entry is classified independently:
//
//     status / statusRaw text (case-insensitive substring match, applied to
//     the raw variant first, then the presented variant):
//       contains "malicious"          → malicious evidence
//       contains "suspicious"         → suspicious evidence
//       contains "no specific threat" → benign evidence
//       contains "no threat"          → benign evidence
//       contains "clean"              → benign evidence
//       contains "whitelist"          → benign evidence (vendor allowlist)
//       "error", or a non-null error_message on an otherwise unclassified
//         entry                       → errored evidence
//       anything else ("no-classification", "in-queue", empty, unrecognized)
//         → unresolved evidence
//     a null or structurally unusable entry is missing evidence — the scanner
//     never produced data. Missing is explicitly NOT benign: it contributes no
//     clean evidence and can never be the basis of a clean verdict, though it
//     also does not itself contradict one supported by other scanners.
//
//   - The deprecated `scanners` array is classified with the same rules, so
//     records still carrying it are judged identically.
//   - Detection counts (positives/percent) and the SHA-256 digest are not
//     verdicts; presence of a hash alone can never make a URL safe or unsafe.
//
// Aggregation ladder — first match wins, worst available evidence is
// preserved:
//
//  1. any malicious evidence                        → "malicious"
//  2. else any suspicious evidence                  → "suspicious"
//     (suspicious outranks clean: conflicting benign and suspicious scanner
//     output is handled conservatively)
//  3. else benign evidence exists, with no unresolved and
//     no errored scanner remaining                  → "no_threat_detected"
//  4. else unresolved or errored scanners remain    → "inconclusive"
//     (the finished scan lacks sufficient, unconflicting evidence)
//  5. else nothing usable was evaluated — every scanner entry was missing →
//     "unknown"
//
// Provider-level failures are handled upstream in the orchestration; an error
// response can never reach a verdict at all.

import (
	"strings"

	"cyberguard/internal/hybridanalysis"
	"cyberguard/internal/models"
)

// evidenceClass buckets one scanner entry's output.
type evidenceClass int

const (
	evMissing    evidenceClass = iota // null/absent/unusable entry: no scan data
	evError                           // scanner acknowledged a failure
	evUnresolved                      // scan produced no classification ("no-classification", "in-queue", …)
	evBenign                          // clean / allowed / no specific threat
	evSuspicious
	evMalicious
)

// normalizeVerdict maps a finished provider result onto the verdict
// vocabulary. The bool result is false when the caller must keep the verdict
// null: for any unfinished scan, and — defensively — for results with no
// scanner data at all, which map to VerdictUnknown rather than to a final
// answer.
func normalizeVerdict(r hybridanalysis.Result) (string, bool) {
	if !r.Finished {
		// The provider itself has not completed the analysis: there is
		// nothing to normalize, and a null verdict is the honest output.
		return "", false
	}

	counts := map[evidenceClass]int{}

	// scanners_v2: the documented current shape. Entries are nullable; keys
	// are the provider's.
	for _, entry := range r.ScannersV2 {
		obj, ok := entry.(map[string]any)
		if !ok {
			// null or non-object entry: the scanner never produced data.
			counts[evMissing]++
			continue
		}
		counts[classifyEntry(
			optionalString(obj["statusRaw"]),
			optionalString(obj["status"]),
			optionalString(obj["error_message"]),
		)]++
	}

	// scanners: the deprecated array, classified with the same rules so
	// provider shapes do not produce different verdicts.
	for _, sc := range r.Scanners {
		errMsg := ""
		if sc.ErrorMessage != nil {
			errMsg = *sc.ErrorMessage
		}
		counts[classifyEntry(sc.StatusRaw, sc.Status, errMsg)]++
	}

	switch {
	case counts[evMalicious] > 0:
		// Rule 1: confirmed malicious classification.
		return models.VerdictMalicious, true
	case counts[evSuspicious] > 0:
		// Rule 2: confirmed suspicious classification outranks benign.
		return models.VerdictSuspicious, true
	case counts[evBenign] > 0 && counts[evUnresolved] == 0 && counts[evError] == 0:
		// Rule 3: every scanner that produced data reported benign, so and
		// only so the finished results genuinely support a clean
		// conclusion. Missing entries contributed nothing to this.
		return models.VerdictNoThreat, true
	case counts[evUnresolved] > 0 || counts[evError] > 0:
		// Rule 4: finished but with insufficient or conflicting evidence.
		return models.VerdictInconclusive, true
	default:
		// Rule 5: the finished response evaluated nothing usable.
		return models.VerdictUnknown, true
	}
}

// classifyEntry applies the documented text rules to one entry.
func classifyEntry(statusRaw, status, errorMessage string) evidenceClass {
	// The raw variant is authoritative when present; the presented variant
	// appends the "whitelisted" UI status.
	for _, text := range []string{strings.ToLower(statusRaw), strings.ToLower(status)} {
		switch {
		case containsToken(text, "malicious"):
			return evMalicious
		case containsToken(text, "suspicious"):
			return evSuspicious
		case containsToken(text, "no specific threat"),
			containsToken(text, "no threat"),
			containsToken(text, "clean"),
			containsToken(text, "whitelist"):
			return evBenign
		}
	}
	if strings.EqualFold(strings.TrimSpace(statusRaw), "error") ||
		strings.EqualFold(strings.TrimSpace(status), "error") ||
		strings.TrimSpace(errorMessage) != "" {
		// A failed scanner is never safe: it owns no classification.
		return evError
	}
	return evUnresolved
}

// containsToken reports whether text contains the keyword as a substring.
func containsToken(text, keyword string) bool {
	return text != "" && strings.Contains(text, keyword)
}

// optionalString reads a JSON object field that may be a string or null.
func optionalString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	return ""
}
