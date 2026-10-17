package app

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/providers/hybridanalysis"
)

// Provider selection decides whether anything leaves the machine, so it is
// tested at the boundary rather than trusted.

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(discard{}, nil))
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

// baseConfig loads the real defaults and then overrides the provider directly.
//
// The selection is applied to the struct rather than through the environment so
// these tests can run in parallel; t.Setenv forbids that, and nothing here
// needs to exercise the environment path — config's own tests already do.
func baseConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	cfg.AnalysisProvider = config.ProviderHybridAnalysis
	return cfg
}

// Mock mode must never build the real client, whatever else is configured.
func TestNewProviderMockModeIgnoresTheAPIKey(t *testing.T) {
	t.Parallel()

	cfg := baseConfig(t)
	cfg.AnalysisProvider = config.ProviderMock
	// A key is present but must be irrelevant: if the real client were built
	// here, a mistake elsewhere would start spending quota from a machine the
	// operator believed was offline.
	cfg.HybridAnalysisAPIKey = "not-a-real-key-but-well-formed"

	p, err := NewProvider(cfg, quietLogger())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.Name() == hybridanalysis.ProviderName {
		t.Fatal("mock mode built the real Hybrid Analysis client")
	}
	if p.Name() != "mock" {
		t.Errorf("provider name = %q, want mock", p.Name())
	}
}

// Mock mode needs no credentials at all.
func TestNewProviderMockModeNeedsNoCredentials(t *testing.T) {
	t.Parallel()

	cfg := baseConfig(t)
	cfg.AnalysisProvider = config.ProviderMock
	cfg.HybridAnalysisAPIKey = ""

	p, err := NewProvider(cfg, quietLogger())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p == nil {
		t.Fatal("NewProvider returned no provider")
	}
}

// Hybrid Analysis mode must never silently fall back to the mock. A silent
// fallback would make the integration look tested when it is not.
func TestNewProviderNeverFallsBackToMock(t *testing.T) {
	t.Parallel()

	cfg := baseConfig(t)
	cfg.AnalysisProvider = config.ProviderHybridAnalysis
	cfg.HybridAnalysisAPIKey = ""

	p, err := NewProvider(cfg, quietLogger())
	if err == nil {
		t.Fatal("hybrid-analysis mode without a key was accepted")
	}
	if p != nil {
		t.Error("a provider was returned despite the error")
	}
	if !strings.Contains(err.Error(), "HYBRID_ANALYSIS_API_KEY") {
		t.Errorf("error = %q, want it to name the missing setting", err)
	}
	if !strings.Contains(err.Error(), config.ProviderMock) {
		t.Errorf("error = %q, want it to offer the mock mode as the fix", err)
	}
}

// With a key, the real client must be built. No request is made here: the
// client is lazy and only dials on the first command.
func TestNewProviderBuildsTheRealClientWhenConfigured(t *testing.T) {
	t.Parallel()

	cfg := baseConfig(t)
	cfg.AnalysisProvider = config.ProviderHybridAnalysis
	cfg.HybridAnalysisAPIKey = "not-a-real-key-but-well-formed"

	p, err := NewProvider(cfg, quietLogger())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}
	if p.Name() != hybridanalysis.ProviderName {
		t.Errorf("provider name = %q, want %q", p.Name(), hybridanalysis.ProviderName)
	}
}

// The quota probe is a live request. It must not run in mock mode, and this
// test is what stops that from regressing.
func TestReportProviderStateSkipsTheQuotaProbeInMockMode(t *testing.T) {
	t.Parallel()

	cfg := baseConfig(t)
	cfg.AnalysisProvider = config.ProviderMock

	var logs strings.Builder
	logger := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))

	p, err := NewProvider(cfg, logger)
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	// A nil context would panic on any timeout, so a background one is used;
	// the mock probe must return without touching it.
	ReportProviderState(context.Background(), cfg, p, logger)

	out := logs.String()
	if !strings.Contains(out, "external_requests") {
		t.Errorf("the mock report did not state that no external requests are made:\n%s", out)
	}
	if strings.Contains(out, "provider quota") {
		t.Errorf("a quota probe was reported in mock mode:\n%s", out)
	}
	if strings.Contains(out, "environment_id") {
		t.Errorf("a sandbox environment was reported in mock mode:\n%s", out)
	}
}

// A nil provider must be tolerated: the API can be built before one exists.
func TestReportProviderStateToleratesNil(t *testing.T) {
	t.Parallel()

	cfg := baseConfig(t)
	ReportProviderState(t.Context(), cfg, nil, quietLogger())
}

// The real-provider report path must not panic when the quota probe fails.
func TestReportProviderStateSurvivesAnUnreachableProvider(t *testing.T) {
	t.Parallel()

	cfg := baseConfig(t)
	cfg.AnalysisProvider = config.ProviderHybridAnalysis
	cfg.HybridAnalysisAPIKey = "not-a-real-key-but-well-formed"
	// An unroutable address, so the probe fails fast without leaving the host.
	cfg.HybridAnalysisBaseURL = "http://127.0.0.1:1/api/v2"
	cfg.HybridAnalysisTimeout = 100 * time.Millisecond

	p, err := NewProvider(cfg, quietLogger())
	if err != nil {
		t.Fatalf("NewProvider: %v", err)
	}

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	// Must return rather than hang or panic.
	done := make(chan struct{})
	go func() {
		defer close(done)
		ReportProviderState(ctx, cfg, p, quietLogger())
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("ReportProviderState hung on an unreachable provider")
	}
}
