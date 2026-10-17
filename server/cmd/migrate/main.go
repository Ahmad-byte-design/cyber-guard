// Command migrate brings the database schema up to date.
//
// It creates every index the repositories rely on, and it is idempotent:
// running it against an already-migrated database is a no-op.
//
// # Why this is a separate program
//
// The alternative — creating indexes during application startup — was rejected
// in the implementation plan, for good reasons: a large collection would make
// every replica restart wait on an index build, and a failed migration would
// take the service down rather than reporting a degraded one.
//
// But running it *nowhere* is worse than either. An unmigrated database does not
// fail loudly; it silently loses the guarantees the system is built on:
//
//   - the partial unique index that makes "one provider submission per URL"
//     real. Without it, concurrent requests create duplicate scans and duplicate
//     provider submissions, and neither the application nor the logs look
//     wrong.
//   - the TTL index that reaps encrypted URLs if explicit deletion is missed.
//   - the index backing the verdict cache lookup on the hot path.
//
// Those are exactly the failures that are invisible until someone notices them.
// So the migration runs as its own step, the application refuses to serve
// until it has succeeded, and compose wires the two together.
//
// # Running it
//
//	docker compose run --rm migrate
//	docker compose run --rm migrate -verify   # check without creating
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/logging"
	"cyberguard/server/internal/platform/mongostore"
)

// Overridden at build time via -ldflags "-X main.version=...".
var (
	version   = "dev"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	printVersion := flag.Bool("version", false, "print version information and exit")
	verifyOnly := flag.Bool("verify", false, "report which indexes are missing without creating them")
	flag.Parse()

	if *printVersion {
		fmt.Printf("cyberguard-migrate %s (commit %s, built %s)\n", version, commit, buildTime)
		return
	}

	if err := run(*verifyOnly); err != nil {
		fmt.Fprintf(os.Stderr, "migrate: %v\n", err)
		os.Exit(1)
	}
}

func run(verifyOnly bool) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := logging.Default(cfg.LogLevel, cfg.LogFormat)
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	connectCtx, cancel := context.WithTimeout(ctx, cfg.MongoConnectTimeout)
	defer cancel()

	store, err := mongostore.Connect(connectCtx, mongostore.Options{
		URI:            cfg.MongoURI,
		Database:       cfg.MongoDatabase,
		ConnectTimeout: cfg.MongoConnectTimeout,
		PingTimeout:    cfg.MongoPingTimeout,
	})
	if err != nil {
		return fmt.Errorf("mongodb: %w", err)
	}
	defer func() { _ = store.Disconnect(context.WithoutCancel(ctx)) }()

	logger.Info("connected", slog.String("database", cfg.MongoDatabase))

	if verifyOnly {
		return verify(ctx, store, logger)
	}

	start := time.Now()
	if err := store.EnsureIndexes(ctx); err != nil {
		return fmt.Errorf("create indexes: %w", err)
	}
	logger.Info("indexes ensured", slog.Duration("took", time.Since(start)))

	// Report what now exists, so the log is evidence rather than a promise.
	for _, collection := range []string{
		mongostore.CollectionScans,
		mongostore.CollectionAssessments,
		mongostore.CollectionTransientURLs,
	} {
		indexes, err := store.ListIndexes(ctx, collection)
		if err != nil {
			logger.Warn("listing indexes failed", slog.String("collection", collection))
			continue
		}
		names := make([]string, 0, len(indexes))
		for _, idx := range indexes {
			if name, ok := idx["name"].(string); ok {
				names = append(names, name)
			}
		}
		logger.Info("indexes present", slog.String("collection", collection), slog.Any("indexes", names))
	}

	return nil
}

// verify reports what is missing without changing anything.
//
// It exists so an operator can answer "is this database migrated?" without
// mutating it, which is the question to ask before wondering why deduplication
// is not working.
func verify(ctx context.Context, store *mongostore.Store, logger *slog.Logger) error {
	var missing []string

	for _, collection := range []string{
		mongostore.CollectionScans,
		mongostore.CollectionAssessments,
		mongostore.CollectionTransientURLs,
	} {
		indexes, err := store.ListIndexes(ctx, collection)
		if err != nil {
			return fmt.Errorf("list indexes on %s: %w", collection, err)
		}
		names := make([]string, 0, len(indexes))
		for _, idx := range indexes {
			if name, ok := idx["name"].(string); ok {
				names = append(names, name)
			}
		}
		logger.Info("indexes present", slog.String("collection", collection), slog.Any("indexes", names))

		// The default _id index is the only one MongoDB creates by itself.
		if len(names) <= 1 {
			missing = append(missing, collection)
		}
	}

	if len(missing) > 0 {
		return fmt.Errorf("these collections have only the default index, so their guarantees "+
			"are not in force (deduplication, TTL expiry, cache lookup): %v; run: "+
			"docker compose run --rm migrate", missing)
	}

	logger.Info("every collection is indexed; the schema is up to date")
	return nil
}
