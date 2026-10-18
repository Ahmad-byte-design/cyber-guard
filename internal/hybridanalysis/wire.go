package hybridanalysis

import (
	"encoding/json"

	"cyberguard/internal/models"
)

// Wire types for POST /quick-scan/url, transcribed from the official Hybrid
// Analysis API v2 specification (OpenAPI 3.0.0, retrieved 2026-10-17).
//
// The provider marks most fields nullable, so every field it may omit is a
// pointer: decoding an absent value into a plain int or string silently
// produces a zero that looks like a real answer. Decoding itself is tolerant —
// an unexpected field from the provider is ignored, not an error — because
// this service stores the parsed fields it needs and passes `scanners_v2`
// through verbatim, rather than rejecting a live response over a field it
// does not read.

// quickScan is the provider's `QuickScan` schema: the body of a 201 response.
type quickScan struct {
	ID         string          `json:"id"`
	SHA256     *string         `json:"sha256"`
	Finished   bool            `json:"finished"`
	Scanners   []wireScanner   `json:"scanners"`
	ScannersV2 json.RawMessage `json:"scanners_v2"`
	// Whitelist is deprecated and always empty; declared so a live response
	// containing it is expected, unread.
	Whitelist json.RawMessage `json:"whitelist"`
	Reports   []string        `json:"reports"`
}

// wireScanner is the provider's `Scanner` schema (the deprecated array
// element): the union of per-scanner fields the specification documents there.
type wireScanner struct {
	Name         string         `json:"name"`
	Status       string         `json:"status"`
	StatusRaw    string         `json:"statusRaw"`
	ErrorMessage *string        `json:"error_message"`
	Progress     int            `json:"progress"`
	Total        *int           `json:"total"`
	Positives    *int           `json:"positives"`
	Percent      *int           `json:"percent"`
	AntiVirus    []wireAVResult `json:"anti_virus_results"`
}

// wireAVResult is the provider's `AntiVirusResult` schema.
type wireAVResult struct {
	Name        string `json:"name"`
	Result      bool   `json:"result"`
	ThreatFound string `json:"threat_found"`
}

// convertScanners maps provider wire scanners onto the models shape. The only
// translation is field naming; nothing is defaulted or invented.
func convertScanners(in []wireScanner) []models.Scanner {
	if in == nil {
		return nil
	}
	out := make([]models.Scanner, 0, len(in))
	for _, s := range in {
		m := models.Scanner{
			Name:         s.Name,
			Status:       s.Status,
			StatusRaw:    s.StatusRaw,
			ErrorMessage: s.ErrorMessage,
			Progress:     s.Progress,
			Total:        s.Total,
			Positives:    s.Positives,
			Percent:      s.Percent,
		}
		for _, av := range s.AntiVirus {
			m.AntiVirusResults = append(m.AntiVirusResults, models.AntiVirusResult{
				Name:        av.Name,
				Result:      av.Result,
				ThreatFound: av.ThreatFound,
			})
		}
		out = append(out, m)
	}
	return out
}
