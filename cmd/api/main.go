// Command api is the CyberGuard AI HTTP server.
//
// It loads configuration (environment, then .env for local development),
// verifies MongoDB is reachable, and serves the JSON API with graceful
// shutdown so in-flight requests finish before the process exits.
//
// There is one binary and no background work: a submission is handled
// synchronously inside its own request, so the deployment is one process plus
// MongoDB.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cyberguard/internal/config"
	"cyberguard/internal/handlers"
	"cyberguard/internal/hybridanalysis"
	"cyberguard/internal/models"
	"cyberguard/internal/mongodb"
	"cyberguard/internal/services"
)

// Fixed budgets, in one place.
const (
	mongoConnectTimeout = 10 * time.Second
	mongoPingTimeout    = 5 * time.Second
	healthCheckTimeout  = 2 * time.Second
	shutdownTimeout     = 10 * time.Second
)

func main() {
	if err := realMain(); err != nil {
		fmt.Fprintf(os.Stderr, "api: %v\n", err)
		os.Exit(1)
	}
}

// realMain is separated from main so a deferred cleanup cannot run under a
// non-zero exit above.
func realMain() error {
	// .env is loaded explicitly, before configuration, so the same binary
	// works under a process manager (environment only) and on a host
	// (environment + .env); the environment always wins.
	if err := config.LoadDotEnv(".env"); err != nil {
		return fmt.Errorf(".env: %w", err)
	}
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	if cfg.HAAPIKey == "" {
		logger.Warn("HYBRID_ANALYSIS_API_KEY is not set; " +
			"POST /api/v1/check-url will report the provider as unconfigured until it is set")
	}
	logger.Info("configuration loaded",
		slog.Int("port", cfg.Port),
		slog.String("database", cfg.MongoDatabase),
		slog.String("scan_type", cfg.HAScanType),
		slog.String("base_url", cfg.HABaseURL),
		slog.Duration("assessment_ttl", cfg.AssessmentTTL),
		slog.Duration("poll_interval", cfg.HAPollInterval),
		slog.Any("cors_origins", cfg.CORSAllowedOrigins),
	)

	// signal.NotifyContext is installed before connecting so a SIGTERM during
	// a slow database connection still cancels the attempt.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := mongodb.Connect(ctx, mongodb.Options{
		URI:            cfg.MongoURI,
		Database:       cfg.MongoDatabase,
		ConnectTimeout: mongoConnectTimeout,
		PingTimeout:    mongoPingTimeout,
	})
	if err != nil {
		return fmt.Errorf("mongodb: %w", err)
	}
	defer func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := db.Disconnect(closeCtx); err != nil {
			logger.Error("failed to close MongoDB", slog.String("error", err.Error()))
		}
	}()
	logger.Info("mongodb connected", slog.String("database", cfg.MongoDatabase))

	store := mongodb.NewStore(db.Database(), models.SubmissionCollection)

	// Index creation is idempotent and cheap; failing here means the one
	// query this service depends on would sort in memory forever, so it is
	// a startup error rather than a warning.
	if err := store.EnsureIndexes(ctx); err != nil {
		return fmt.Errorf("mongodb: %w", err)
	}

	var analyzer services.URLAnalyzer
	if cfg.HAAPIKey != "" {
		analyzer, err = hybridanalysis.New(hybridanalysis.Options{
			BaseURL:  cfg.HABaseURL,
			APIKey:   cfg.HAAPIKey,
			ScanType: cfg.HAScanType,
			Timeout:  cfg.HATimeout,
			Logger:   logger,
		})
		if err != nil {
			return fmt.Errorf("analysis provider: %w", err)
		}
	}

	svc := services.New(store, analyzer, services.ServiceOptions{
		AssessmentTTL: cfg.AssessmentTTL,
		PollInterval:  cfg.HAPollInterval,
		// The wait budget draws from the same provider budget the client
		// uses; WriteTimeout below adds the recording margin on top.
		WaitBudget: cfg.HATimeout,
	})

	srv := &http.Server{
		Addr: fmt.Sprintf(":%d", cfg.Port),
		Handler: handlers.New(handlers.Dependencies{
			Config:  cfg,
			Logger:  logger,
			Service: svc,
			Ping: func(ctx context.Context) error {
				pingCtx, cancel := context.WithTimeout(ctx, healthCheckTimeout)
				defer cancel()
				return db.Ping(pingCtx)
			},
		}).Handler(),
		// Bound header and body reads so a stalled client cannot pin a
		// goroutine. WriteTimeout must exceed the provider budget, because
		// check-url may wait for the provider's result retrieval.
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      cfg.HATimeout + 15*time.Second,
		IdleTimeout:       60 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("api listening", slog.String("addr", srv.Addr))
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("listen: %w", err)
	case <-ctx.Done():
		logger.Info("shutdown signal received", slog.Duration("grace", shutdownTimeout))
	}

	// ctx is already cancelled by the signal, so shutdown needs its own
	// deadline detached from it — otherwise every request context is dead
	// before in-flight handlers can finish.
	shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		// Force-close so a stuck connection cannot block container exit.
		_ = srv.Close()
		return fmt.Errorf("shutdown: %w", err)
	}

	logger.Info("api stopped cleanly")
	return nil
}
