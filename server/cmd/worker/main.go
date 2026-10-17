// Command worker runs asynchronous scan jobs: claiming them from Redis,
// submitting the URL to the analysis provider, polling with backoff, and
// persisting the normalised verdict to MongoDB.
//
// The worker is the only process that contacts the provider. The API accepts a
// submission and returns immediately, so no HTTP request is ever held across a
// detonation.
//
// Per ADR 0013 the queue payload is a scan ID; the raw URL is read from the
// encrypted transient_urls collection and deleted as it is read, so the
// plaintext exists in this process only for the duration of one submission.
//
// Recovery is in internal/scans. The short version: MongoDB is the ledger and
// Redis is only delivery, so a lost or failed enqueue delays work rather than
// losing it. See the scans package comment.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cyberguard/server/internal/app"
	"cyberguard/server/internal/config"
	"cyberguard/server/internal/logging"
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
		fmt.Printf("cyberguard-worker %s (commit %s, built %s)\n", version, commit, buildTime)
		return
	}

	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "worker: %v\n", err)
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
		logger.Warn("URL_FINGERPRINT_HMAC_KEY is unset; fingerprints will not match the API's")
	}

	// signal.NotifyContext is installed before connecting so a SIGTERM during a
	// slow database connection still cancels the attempt.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	datastores, err := app.ConnectDatastores(ctx, cfg, logger)
	if err != nil {
		return fmt.Errorf("datastores: %w", err)
	}

	// Fatal, and deliberately so. A worker that started without the provider it
	// was configured for would fail every job with an error the operator then
	// had to diagnose from the job side, instead of being told at startup that
	// the configuration is wrong.
	provider, err := app.NewProvider(cfg, logger)
	if err != nil {
		return fmt.Errorf("analysis provider: %w", err)
	}
	app.ReportProviderState(ctx, cfg, provider, logger)

	// The rate limiter belongs to the API process, which is the only one that
	// accepts client requests. The worker holds no limiter and no guard: it
	// must drain whatever was already accepted.
	scanService, err := app.NewScanService(cfg, datastores.Mongo, datastores.Redis, provider, logger, nil)
	if err != nil {
		closeDatastores(datastores, logger)
		return fmt.Errorf("scan service: %w", err)
	}

	rulesetService, err := app.NewRulesetService(cfg, datastores.Mongo, logger)
	if err != nil {
		closeDatastores(datastores, logger)
		return fmt.Errorf("ruleset service: %w", err)
	}
	if rulesetService != nil {
		// Rebuilding on a timer rather than per scan: a burst of completions
		// must not cause a burst of rebuilds, and an unchanged rule set does not
		// increment the version, so an extra rebuild is harmless but not free.
		go rebuildRulesets(ctx, rulesetService, cfg.RulesetRebuildInterval, logger)
	}

	// Run blocks until the context is cancelled, then waits for in-flight jobs
	// to finish or be abandoned for the reconciler to pick up.
	runErr := scanService.Run(ctx)

	logger.Info("shutdown signal received")
	closeCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), app.ShutdownTimeout(cfg))
	defer cancel()

	if err := datastores.Close(closeCtx); err != nil {
		return fmt.Errorf("close datastores: %w", err)
	}
	logger.Info("worker stopped cleanly")
	return runErr
}

func closeDatastores(d *app.Datastores, logger *slog.Logger) {
	closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := d.Close(closeCtx); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("failed to close datastores", slog.String("error", err.Error()))
	}
}

// rebuildRulesets periodically regenerates and publishes the ruleset.
//
// It runs for the worker's lifetime and stops with the worker. A failure is
// logged and retried on the next tick: a ruleset that cannot be rebuilt leaves
// the previously published one in force, which is strictly better than
// publishing an empty one and telling every client it is unprotected.
func rebuildRulesets(ctx context.Context, service *rulesetapi.Service, interval time.Duration, logger *slog.Logger) {
	if interval <= 0 {
		interval = time.Minute
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	// Publish once at startup, so a freshly-started worker does not leave the
	// ruleset stale for a whole interval.
	rebuildOnce(ctx, service, logger)

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			rebuildOnce(ctx, service, logger)
		}
	}
}

func rebuildOnce(ctx context.Context, service *rulesetapi.Service, logger *slog.Logger) {
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
