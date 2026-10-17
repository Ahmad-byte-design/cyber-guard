// Package verdicts owns CyberGuard's security verdict vocabulary.
//
// This package defines what each verdict *means*. It performs no provider
// mapping: only the adapter for a given provider knows that provider's strings,
// so the translation table lives beside the adapter that owns it. Keeping the
// target vocabulary here means the rest of the system reasons about five values
// and never about any provider's vocabulary.
//
// # Semantics
//
//   - [Malicious] The provider positively identified malicious behaviour.
//   - [Suspicious] Indicators were present but below the malicious threshold.
//   - [NoThreatDetected] The analysis completed and found no indicators
//     sufficient to classify the sample. This is **not** a safety guarantee and
//     must never be rendered as "safe", "trusted" or "secure".
//   - [Inconclusive] The analysis completed but the result does not support any
//     classification.
//   - [Unknown] It could not be determined: the analysis failed, timed out,
//     was refused, or returned something unrecognised.
//
// See ADR 0011 for why no_threat_detected replaced benign.
package verdicts

import "strings"

// Verdict is CyberGuard's normalised security verdict.
type Verdict string

const (
	// Malicious means malicious behaviour was positively identified.
	Malicious Verdict = "malicious"

	// Suspicious means indicators were present but below the malicious
	// threshold.
	Suspicious Verdict = "suspicious"

	// NoThreatDetected means the analysis completed and found no indicators
	// sufficient to classify the sample.
	//
	// It is an absence of evidence, not evidence of absence. It is never a
	// safety guarantee and never authorises a blocking rule.
	NoThreatDetected Verdict = "no_threat_detected"

	// Inconclusive means the analysis completed without a conclusive result.
	// This is distinct from Unknown: the analysis *ran*.
	Inconclusive Verdict = "inconclusive"

	// Unknown means it could not be determined at all.
	Unknown Verdict = "unknown"
)

// Valid reports whether v is one of the five defined verdicts.
func (v Verdict) Valid() bool {
	switch v {
	case Malicious, Suspicious, NoThreatDetected, Inconclusive, Unknown:
		return true
	default:
		return false
	}
}

// String returns the verdict's wire value.
func (v Verdict) String() string { return string(v) }

// All returns every verdict, in severity order. Useful for exhaustive tests and
// for validating a mapping table.
func All() []Verdict {
	return []Verdict{Malicious, Suspicious, NoThreatDetected, Inconclusive, Unknown}
}

// NormaliseLower lower-cases and trims a provider classification so a mapping
// table can match it without repeating the cleanup at every comparison.
//
// Provider vocabularies are case-inconsistent in practice, and the specification
// for Hybrid Analysis declares the field as a free-form string with no
// enumerated values. Matching on a cleaned copy, while leaving the original
// untouched, keeps the translation predictable without mutating provider data.
func NormaliseLower(classification string) string {
	return strings.ToLower(strings.TrimSpace(classification))
}
