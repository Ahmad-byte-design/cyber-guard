// Command api serves the CyberGuard JSON API.
//
// It validates configuration at startup, opens the MongoDB and Redis
// connections, exposes liveness and readiness probes, and shuts down
// gracefully so in-flight requests finish before the container exits.
//
// The API accepts submissions and reads status. It never contacts the analysis
// provider: all provider work happens in the worker, so a slow detonation can
// never hold an HTTP request open.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cyberguard/server/internal/app"
	"cyberguard/server/internal/config"
	"cyberguard/server/internal/httpapi"
	"cyberguard/server/internal/logging"
	"cyberguard/server/internal/ratelimit"
)

// Overridden at build time via -ldflags "-X main.version=...".
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	printVersion := flag.Bool("version", false, "print version information and exit")
	flag.Parse()

	if *printVersion {
		fmt.Printf("cyberguard-api %s (commit %s, built %s)\n", version, commit, buildTime)
		return
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "api: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := logging.Default(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)

	if !cfg.HasFingerprintKey() {
		logger.Warn("URL_FINGERPRINT_HMAC_KEY is unset; readiness will fail and URL submission is disabled")
	}
	if !cfg.HasEncryptionKey() {
		logger.Error("URL_ENCRYPTION_KEY is unset or shorter than 32 bytes; the scan pipeline cannot start")
	}
	if cfg.UsesMockProvider() {
		logger.Warn("running with the MOCK analysis provider; no URL will leave this machine")
	} else if !cfg.HasProviderCredentials() {
		logger.Error("HYBRID_ANALYSIS_API_KEY is unset while ANALYSIS_PROVIDER=hybrid-analysis")
	}

	// signal.NotifyContext is installed before connecting so a SIGTERM during
	// a slow database connection still cancels the attempt.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	datastores, err := app.ConnectDatastores(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("datastores: %w", err)
	}

	logger.Info("analysis provider selected", slog.String("provider", cfg.AnalysisProvider))

	// The API builds the provider but never calls it. It is constructed so both
	// processes agree on configuration and so provider-scoped settings are
	// validated identically; no request from this process reaches a provider.
	provider, err := app.NewProvider(cfg, logger)
	if err != nil {
		return fmt.Errorf("analysis provider: %w", err)
	}

	limiter := ratelimit.New(datastores.Redis.Redis(), time.Now)

	scanService, err := app.NewScanService(cfg, datastores.Mongo, datastores.Redis, provider, logger,
		httpapi.NewFingerprintGuard(limiter, cfg))
	if err != nil {
		return fmt.Errorf("scan service: %w", err)
	}

	rulesetService, err := app.NewRulesetService(cfg, datastores.Mongo, logger)
	if err != nil {
		return fmt.Errorf("ruleset service: %w", err)
	}

	srv := &http.Server{
		Addr: cfg.HTTPAddr,
		Handler: httpapi.NewServer(httpapi.Dependencies{
			Config:   cfg,
			Logger:   logger,
			Health:   datastores.Health,
			Scans:    scanService,
			Limiter:  limiter,
			Rulesets: rulesetService,
		}).Handler(),
		// Bound header reads so a stalled client cannot pin a goroutine
		// forever; the scan pipeline runs elsewhere, so this stays tight.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("api listening", slog.String("addr", cfg.HTTPAddr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		closeDatastores(datastores, logger)
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		logger.Info("shutdown signal received", slog.Duration("grace", cfg.ShutdownTimeout))
	}

	// ctx is already cancelled by the signal, so shutdown needs its own
	// deadline detached from it — otherwise every request context is dead
	// before in-flight handlers can finish.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), app.ShutdownTimeout(cfg))
	defer cancel()

	shutdownErr := srv.Shutdown(shutdownCtx)
	if shutdownErr != nil {
		// Force-close so a stuck connection cannot block container exit.
		_ = srv.Close()
	}

	closeErr := datastores.Close(shutdownCtx)
	if shutdownErr != nil {
		return fmt.Errorf("shutdown: %w", shutdownErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close datastores: %w", closeErr)
	}

	logger.Info("api stopped cleanly")
	return nil
}

func closeDatastores(d *app.Datastores, logger *slog.Logger) {
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(closeCtx); err != nil {
		logger.Error("failed to close datastores", slog.String("error", err.Error()))
	}
}
