package health

import (
	"context"
	"errors"
	"testing"
	"time"
)

// stubCheck returns a fixed error from Ping.
type stubCheck struct {
	err error
	// delay simulates a slow dependency.
	delay time.Duration
}

func (s stubCheck) Ping(ctx context.Context) error {
	if s.delay > 0 {
		select {
		case <-time.After(s.delay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return s.err
}

func TestCheckerReportsEveryDependency(t *testing.T) {
	t.Parallel()

	checker := NewChecker(time.Second,
		Named{Name: "mongodb", Check: stubCheck{}},
		Named{Name: "provider_registry", Check: stubCheck{}},
	)

	ready, reports := checker.Run(t.Context())

	if !ready {
		t.Error("Run reported not-ready with all dependencies healthy")
	}
	if len(reports) != 2 {
		t.Fatalf("got %d reports, want 2", len(reports))
	}
	for _, r := range reports {
		if !r.OK {
			t.Errorf("check %q reported not-ok", r.Name)
		}
		if r.Why != "" {
			t.Errorf("check %q has a why for a healthy dependency: %q", r.Name, r.Why)
		}
	}
}

func TestCheckerFailsWhenAnyDependencyIsDown(t *testing.T) {
	t.Parallel()

	checker := NewChecker(time.Second,
		Named{Name: "mongodb", Check: stubCheck{}},
		Named{Name: "provider_registry", Check: stubCheck{err: errors.New("dial tcp: connection refused: credentials must not appear")}},
	)

	ready, reports := checker.Run(t.Context())

	if ready {
		t.Error("Run reported ready with a dependency down")
	}

	var registryReport *Report
	for i := range reports {
		if reports[i].Name == "provider_registry" {
			registryReport = &reports[i]
		}
	}
	if registryReport == nil {
		t.Fatal("no report for the failed dependency")
	}
	if registryReport.OK {
		t.Error("the report is ok despite a failing probe")
	}

	// This endpoint is unauthenticated, so the payload must not carry driver
	// error text, which can embed hosts, topology and credentials.
	if contains := registryReport.Why; contains == "" {
		t.Error("failed check has no why")
	} else if len(contains) != len("dependency unavailable") {
		t.Errorf("why = %q, want the generic message with no driver detail", contains)
	}
}

func TestCheckerWithNoChecksIsReady(t *testing.T) {
	t.Parallel()

	ready, reports := NewChecker(time.Second).Run(t.Context())
	if !ready {
		t.Error("a checker with no dependencies should be ready")
	}
	if len(reports) != 0 {
		t.Errorf("got %d reports, want 0", len(reports))
	}
}

// A probe that hangs must not hang the readiness endpoint.
func TestCheckerBoundsEachProbeWithTimeout(t *testing.T) {
	t.Parallel()

	checker := NewChecker(20*time.Millisecond,
		Named{Name: "slow", Check: stubCheck{delay: 5 * time.Second}},
	)

	start := time.Now()
	ready, reports := checker.Run(t.Context())
	elapsed := time.Since(start)

	if ready {
		t.Error("a hanging dependency must not report ready")
	}
	if len(reports) != 1 || reports[0].OK {
		t.Errorf("expected one failed report, got %+v", reports)
	}
	if elapsed > time.Second {
		t.Errorf("probe took %s; the timeout was not applied", elapsed)
	}
}

// A non-positive timeout would otherwise leave the probe unbounded.
func TestNewCheckerDefaultsInvalidTimeout(t *testing.T) {
	t.Parallel()

	for _, tc := range []time.Duration{0, -time.Second} {
		checker := NewChecker(tc, Named{Name: "slow", Check: stubCheck{delay: 5 * time.Second}})

		start := time.Now()
		checker.Run(t.Context())
		elapsed := time.Since(start)

		// The stub takes 5s if no bound is applied. Anything materially under
		// that proves a default was substituted.
		if elapsed >= 5*time.Second {
			t.Errorf("NewChecker(%s) left the probe unbounded: it ran for %s", tc, elapsed)
		}
	}
}

// The caller may cancel the whole probe run.
func TestCheckerHonoursContextCancellation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	checker := NewChecker(time.Second,
		Named{Name: "slow", Check: stubCheck{delay: 5 * time.Second}},
	)

	start := time.Now()
	if ready, _ := checker.Run(ctx); ready {
		t.Error("expected not-ready with a cancelled context")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cancelled run took %s", elapsed)
	}
}
