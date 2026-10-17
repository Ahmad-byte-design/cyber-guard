package main

import (
	"context"
	"errors"
	"testing"

	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/providers/mock"
)

// A job that already carries a provider scan ID must never be submitted again.
// This is the guard against a retried job spending quota twice.
func TestEnsureSubmittedReusesExistingProviderScanID(t *testing.T) {
	t.Parallel()

	p := mock.New()
	const existing = "job-already-submitted"

	got, err := ensureSubmitted(t.Context(), p, scanRecord{
		ScanID:         "scan_1",
		ProviderScanID: existing,
	}, "https://example.test/login")
	if err != nil {
		t.Fatalf("ensureSubmitted: %v", err)
	}
	if got != existing {
		t.Errorf("provider scan id = %q, want the existing %q", got, existing)
	}
	if n := p.SubmitCount(); n != 0 {
		t.Errorf("provider was called %d times, want 0 for an already-submitted scan", n)
	}
}

func TestEnsureSubmittedSubmitsWhenNoProviderScanID(t *testing.T) {
	t.Parallel()

	p := mock.New()

	got, err := ensureSubmitted(t.Context(), p, scanRecord{ScanID: "scan_1"}, "https://example.test/login")
	if err != nil {
		t.Fatalf("ensureSubmitted: %v", err)
	}
	if got == "" {
		t.Error("provider scan id is empty")
	}
	if n := p.SubmitCount(); n != 1 {
		t.Errorf("provider called %d times, want 1", n)
	}
}

// Retrying after a failure must reuse the ID from the first attempt, not submit
// again. This is the exact sequence an ambiguous submission timeout produces.
func TestEnsureSubmittedIsIdempotentAcrossRetries(t *testing.T) {
	t.Parallel()

	p := mock.New()
	record := scanRecord{ScanID: "scan_1"}

	first, err := ensureSubmitted(t.Context(), p, record, "https://example.test/login")
	if err != nil {
		t.Fatalf("first ensureSubmitted: %v", err)
	}

	// The worker persists the provider scan ID, then the job is retried.
	record.ProviderScanID = first

	second, err := ensureSubmitted(t.Context(), p, record, "https://example.test/login")
	if err != nil {
		t.Fatalf("second ensureSubmitted: %v", err)
	}
	if second != first {
		t.Errorf("retry produced a different scan id %q, want the persisted %q", second, first)
	}
	if n := p.SubmitCount(); n != 1 {
		t.Errorf("provider called %d times across a retry, want exactly 1", n)
	}
}

// A submission error must propagate and must not invent a scan ID, or the
// worker would poll a handle the provider never issued.
func TestEnsureSubmittedPropagatesSubmissionFailure(t *testing.T) {
	t.Parallel()

	p := mock.New(mock.WithSubmit(func(context.Context, string) (providers.Submission, error) {
		return providers.Submission{}, providers.ErrUnavailable
	}))

	got, err := ensureSubmitted(t.Context(), p, scanRecord{ScanID: "scan_1"}, "https://example.test/login")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !errors.Is(err, providers.ErrUnavailable) {
		t.Errorf("error = %v, want ErrUnavailable", err)
	}
	if got != "" {
		t.Errorf("provider scan id = %q on failure, want empty", got)
	}
}

// A provider that accepts a submission but returns no identifier is a contract
// violation, not a usable result.
func TestEnsureSubmittedRejectsEmptyProviderScanID(t *testing.T) {
	t.Parallel()

	p := mock.New(mock.WithSubmit(func(context.Context, string) (providers.Submission, error) {
		return providers.Submission{ProviderScanID: "  "}, nil
	}))

	if _, err := ensureSubmitted(t.Context(), p, scanRecord{ScanID: "scan_1"}, "https://x.test"); !errors.Is(err, providers.ErrBadResponse) {
		t.Errorf("error = %v, want ErrBadResponse", err)
	}
}

func TestIsPermanent(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"nil", nil, true},
		{"auth failed", providers.ErrAuthFailed, true},
		{"bad response", providers.ErrBadResponse, true},
		{"not configured", providers.ErrNotConfigured, true},
		{"unavailable", providers.ErrUnavailable, false},
		{"rate limited", providers.ErrRateLimited, false},
	}

	for _, tc := range cases {
		if got := isPermanent(tc.err); got != tc.want {
			t.Errorf("isPermanent(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}
