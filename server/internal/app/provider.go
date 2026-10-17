package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/providers"
	"cyberguard/server/internal/providers/hybridanalysis"
	"cyberguard/server/internal/providers/mock"
)

// Choosing the analysis provider, once, for both binaries.
//
// This lives here rather than in either main because the API and the worker
// must agree. If they disagreed — one analysing and one recording, or the API
// writing "hybrid-analysis" on a document the mock produced — the audit trail
// would be wrong in a way nothing would detect.
//
// # No fallback, in either direction
//
// The selection is explicit and the configuration loader refuses an
// unusable combination. There is no path from "mock was asked for" to the real
// service, and none from "the key is missing" to the mock.
//
// That matters most offline. A development machine that silently reached the
// real provider would spend real quota and produce different results on every
// run, so "did my pipeline work?" would have no answer.

// NewProvider builds the analysis provider named by configuration.
//
// The returned provider is always usable. In mock mode it is the offline
// provider, which opens no external connection and needs no credentials; in
// hybrid-analysis mode it is the real client, which requires a key that
// ValidateProviderSelection has already confirmed.
func NewProvider(cfg config.Config, logger *slog.Logger) (providers.AnalysisProvider, error) {
	if err := cfg.ValidateProviderSelection(); err != nil {
		return nil, err
	}

	if cfg.UsesMockProvider() {
		// Logged explicitly so an operator reading the startup output can
		// confirm nothing is leaving the machine, rather than inferring it.
		logger.Warn("using the MOCK analysis provider: URLs are analysed in-process " +
			"and nothing is sent to any external service")
		return mock.Local(), nil
	}

	// The key is read from the environment and handed straight to the adapter.
	// It is never logged, never included in an error, and never returned.
	client, err := hybridanalysis.New(hybridanalysis.Options{
		BaseURL:       cfg.HybridAnalysisBaseURL,
		APIKey:        cfg.HybridAnalysisAPIKey,
		EnvironmentID: cfg.HybridAnalysisEnvironmentID,
		Timeout:       cfg.HybridAnalysisTimeout,
		MaxRetries:    cfg.HybridAnalysisMaxRetries,
		RetryBase:     cfg.HybridAnalysisRetryBase,
		Logger:        logger,
	})
	if err != nil {
		return nil, fmt.Errorf("build provider: %w", err)
	}
	return client, nil
}

// ReportProviderState logs what the selected provider is and, only for the real
// service, whether its quota is already spent.
//
// The quota check is a live request. It is therefore gated on the provider
// actually being Hybrid Analysis — in mock mode there is nothing to ask, and
// calling out would defeat the purpose of running offline.
func ReportProviderState(ctx context.Context, cfg config.Config, provider providers.AnalysisProvider, logger *slog.Logger) {
	if provider == nil {
		return
	}

	if cfg.UsesMockProvider() {
		logger.Info("mock analysis provider ready",
			slog.String("provider", provider.Name()),
			slog.Bool("external_requests", false),
		)
		return
	}

	quota, ok := provider.(*hybridanalysis.Client)
	if !ok {
		return
	}

	logger.Info("analysis provider configured",
		slog.String("provider", quota.Name()),
		slog.Int("environment_id", quota.EnvironmentID()),
		slog.String("environment", hybridanalysis.EnvironmentName(quota.EnvironmentID())),
	)

	// Best-effort: a provider outage must not stop the worker from starting.
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	detonation, quickScan, err := quota.GetQuota(probeCtx)
	if err != nil {
		logger.Warn("provider quota check failed; continuing",
			slog.String("reason", err.Error()))
		return
	}

	logger.Info("provider quota",
		slog.Bool("detonation_reached", detonation),
		slog.Bool("quick_scan_reached", quickScan),
	)
	if detonation || quickScan {
		logger.Warn("provider quota is exhausted; submissions will fail until it resets")
	}
}
