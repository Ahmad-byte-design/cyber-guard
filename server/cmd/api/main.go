// Command api serves the CyberGuard JSON API and runs the scan pipeline.
//
// It validates configuration at startup, opens the MongoDB connection, exposes
// liveness and readiness probes, and shuts down gracefully so in-flight requests
// finish before the container exits.
//
// # The scan runner lives here
//
// This process used to be paired with a separate worker binary talking to a Redis
// queue. Both are gone. The API starts the scan runner as background goroutines
// and the scans collection is the queue, so the deployment is one application
// process plus one datastore.
//
// What that changes, stated plainly:
//
//   - A slow detonation still never holds an HTTP request open. Analysis runs on
//     its own goroutines, and POST /api/v1/check-url still returns 202
//     immediately. The decoupling that mattered was between the request and the
//     analysis, not between two processes.
//   - Horizontal scaling no longer needs anything coordinated: the claim is an
//     atomic lease on a document, so several replicas compete safely for work.
//     It does need the caveat in the rate-limit package: counters are
//     per-process, so the configured limits are per-replica.
//   - Restarting the API stops analysis for as long as the restart takes. There
//     is no second process to keep draining the queue.
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
	"cyberguard/server/internal/rulesetapi"
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

	provider, err := app.NewProvider(cfg, logger)
	if err != nil {
		return fmt.Errorf("analysis provider: %w", err)
	}
	app.ReportProviderState(ctx, cfg, provider, logger)

	// Counters are in-process. See the ratelimit package for what per-process
	// scope means and when it stops being acceptable.
	limiter := ratelimit.New(time.Now)

	scanService, err := app.NewScanService(cfg, datastores.Mongo, provider, logger,
		httpapi.NewFingerprintGuard(limiter, cfg))
	if err != nil {
		return fmt.Errorf("scan service: %w", err)
	}

	// The scan runner starts before the listener so a scan accepted immediately
	// after boot is picked up, rather than waiting out a reconcile interval.
	runnerCtx, stopRunner := context.WithCancel(ctx)
	runnerDone := make(chan struct{})
	go func() {
		defer close(runnerDone)
		if err := scanService.Run(runnerCtx); err != nil && runnerCtx.Err() == nil {
			logger.Error("scan runner stopped with an error", slog.String("reason", err.Error()))
		}
	}()

	rulesetService, err := app.NewRulesetService(cfg, datastores.Mongo, logger)
	if err != nil {
		stopRunner()
		<-runnerDone
		return fmt.Errorf("ruleset service: %w", err)
	}

	// Ruleset generation used to belong to the worker. It belongs to whoever
	// owns the scans, which is now this process, so it moved with them.
	stopRulesets := func() {}
	if rulesetService != nil {
		stopRulesets = startRulesetRebuilder(ctx, rulesetService, cfg.RulesetRebuildInterval, logger)
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
		// forever. The scan runner shares this process but holds no HTTP
		// connection, so this stays tight.
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
		// The listener died on its own, so the signal-driven path below will
		// never run and the background goroutines must be stopped here instead.
		// Leaving them running would keep a process alive that can no longer
		// serve anything.
		stopRunner()
		stopRulesets()
		<-runnerDone
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

	// Stop accepting requests before the runner, then stop the runner before
	// MongoDB. The ordering is not incidental: a runner still polling while the
	// store disconnects turns a clean shutdown into a burst of failed scans, and
	// scans are the thing most expensive to get wrong here.
	stopRunner()
	stopRulesets()
	select {
	case <-runnerDone:
		logger.Info("scan runner stopped cleanly")
	case <-shutdownCtx.Done():
		// A provider call can outlive any shutdown budget. An abandoned job is
		// recovered by the lease rather than lost, so waiting longer would only
		// delay exit for no benefit.
		logger.Warn("scan runner did not stop within the shutdown budget; " +
			"in-flight scans are recovered by lease expiry")
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

// startRulesetRebuilder regenerates and publishes the ruleset on a timer.
//
// It runs for the process's lifetime and stops with it. A failure is logged and
// retried on the next tick: a ruleset that cannot be rebuilt leaves the
// previously published one in force, which is strictly better than publishing
// an empty one and telling every client it is unprotected.
//
// It returns a stop function rather than taking a context of its own, so the
// caller's shutdown sequence can order this against the runner and the store
// explicitly instead of relying on a shared cancellation.
func startRulesetRebuilder(
	ctx context.Context,
	service *rulesetapi.Service,
	interval time.Duration,
	logger *slog.Logger,
) func() {
	if interval <= 0 {
		interval = time.Minute
	}

	done := make(chan struct{})
	loopCtx, cancel := context.WithCancel(ctx)

	go func() {
		defer close(done)

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		// Publish once at startup, so a freshly-started process does not leave
		// the ruleset stale for a whole interval.
		rebuildOnce(loopCtx, service, logger)

		for {
			select {
			case <-loopCtx.Done():
				return
			case <-ticker.C:
				rebuildOnce(loopCtx, service, logger)
			}
		}
	}()

	return func() {
		cancel()
		<-done
	}
}

func rebuildOnce(ctx context.Context, service *rulesetapi.Service, logger *slog.Logger) {
	// Detached from ctx so an in-flight rebuild is allowed to finish rather than
	// being cut off by the cancellation that stopped the ticker.
	buildCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 60*time.Second)
	defer cancel()

	snapshot, changed, err := service.Build(buildCtx)
	switch {
	case errors.Is(err, context.Canceled):
		return
	case err != nil:
		logger.Warn("ruleset rebuild failed; the previously published ruleset stays in force",
			slog.String("reason", err.Error()))
		return
	case !changed:
		// The common case. Not bumping the version is what stops every scan
		// from making every client re-download.
		return
	}

	logger.Info("ruleset published",
		slog.Int64("version", snapshot.Version),
		slog.Int("rules", len(snapshot.Rules)))
}
