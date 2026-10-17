package main

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"cyberguard/server/internal/providers"
)

// scanRecord is the minimum a worker needs to resume a submission without
// re-submitting.
//
// It stands in for the MongoDB document that Phase 3 will provide. Keeping the
// shape this small is deliberate: the retry rule below must be provable without
// a database, because a double submission spends real provider quota.
type scanRecord struct {
	// ScanID is CyberGuard's own identifier.
	ScanID string
	// ProviderScanID is the provider's job identifier, or "" if the URL has
	// never been submitted.
	ProviderScanID string
}

// ensureSubmitted resolves the provider scan ID for a scan.
//
// The rule, which is the whole point of this function:
//
//	A job that already carries a provider scan ID must never be submitted again.
//
// It exists because a submission can fail *ambiguously*. The Hybrid Analysis
// specification declares no idempotency or deduplication token, so a timed-out
// POST may already have been accepted upstream. A worker that retries the POST
// would then submit the same URL twice, spend quota twice, and create two
// sandbox jobs for one request. Polling the existing ID instead is always
// correct and costs nothing.
//
// Phase 4 moves this into internal/scans, where it belongs beside the scan
// lifecycle; it is here now so the rule is implemented and tested before
// anything can depend on it.
func ensureSubmitted(
	ctx context.Context,
	provider providers.AnalysisProvider,
	record scanRecord,
	rawURL string,
) (string, error) {
	if record.ProviderScanID != "" {
		return record.ProviderScanID, nil
	}

	submission, err := provider.SubmitURL(ctx, rawURL)
	if err != nil {
		// The submission outcome is unknown. The caller must persist whatever
		// it knows and leave the scan resumable rather than assuming failure.
		return "", fmt.Errorf("submit for scan %s: %w", record.ScanID, err)
	}

	scanID := strings.TrimSpace(submission.ProviderScanID)
	if scanID == "" {
		return "", fmt.Errorf("submit for scan %s: provider returned no scan id: %w",
			record.ScanID, providers.ErrBadResponse)
	}
	return scanID, nil
}

// isPermanent reports whether an error will not succeed on retry.
//
// Used to decide between rescheduling a job and failing it. Authentication and
// malformed-request failures are permanent; retrying them wastes quota and can
// lock the key.
func isPermanent(err error) bool {
	switch {
	case err == nil:
		return true
	case errors.Is(err, providers.ErrAuthFailed),
		errors.Is(err, providers.ErrBadResponse),
		errors.Is(err, providers.ErrNotConfigured):
		return true
	default:
		return false
	}
}
