// Package app holds dependency wiring shared by the api binary.
//
// The API needs two things: a MongoDB connection and a health checker over it.
// Keeping that in one place stops the mains from drifting, which is the usual
// failure mode of duplicated setup code.
//
// This package contains wiring only: no business logic, no HTTP, no scanning.
package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"cyberguard/server/internal/config"
	"cyberguard/server/internal/health"
	"cyberguard/server/internal/platform/mongostore"
)

// Datastores is the set of external dependencies the process holds open.
type Datastores struct {
	Mongo  *mongostore.Store
	Health *health.Checker
}

// ConnectDatastores opens the MongoDB connection and builds the readiness
// checker over it.
//
// It fails fast: a wrong MONGODB_URI returns an error rather than a
// half-working process. Docker Compose already gates startup on MongoDB
// reporting healthy, so in practice this surfaces genuine misconfiguration.
//
// Redis is gone. It previously provided both the job queue and the rate-limit
// counters; both now live in MongoDB and in process respectively, so a single
// datastore is the only one that can be down.
func ConnectDatastores(ctx context.Context, cfg config.Config, logger *slog.Logger) (*Datastores, error) {
	mongo, err := mongostore.Connect(ctx, mongostore.Options{
		URI:            cfg.MongoURI,
		Database:       cfg.MongoDatabase,
		ConnectTimeout: cfg.MongoConnectTimeout,
		PingTimeout:    cfg.MongoPingTimeout,
	})
	if err != nil {
		return nil, err
	}
	// Database name is safe to log; the URI is not, and is never logged.
	logger.Info("mongodb connected", slog.String("database", cfg.MongoDatabase))

	return &Datastores{
		Mongo: mongo,
		Health: health.NewChecker(cfg.HealthCheckTimeout,
			health.Named{Name: "mongodb", Check: mongo},
		),
	}, nil
}

// Close releases the connection.
//
// It is safe to call more than once and safe to call on a nil receiver, so a
// deferred Close can coexist with an explicit shutdown-path Close.
func (d *Datastores) Close(ctx context.Context) error {
	if d == nil {
		return nil
	}

	var errs []error
	if d.Mongo != nil {
		if err := d.Mongo.Disconnect(ctx); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// ShutdownTimeout returns the bounded context deadline used when closing
// connections during shutdown. It exists so both mains use the same budget.
func ShutdownTimeout(cfg config.Config) time.Duration {
	if cfg.ShutdownTimeout > 0 {
		return cfg.ShutdownTimeout
	}
	return 15 * time.Second
}

// PingAll probes every dependency and returns a combined error, for use in a
// startup self-check or a one-off diagnostic command.
func (d *Datastores) PingAll(ctx context.Context) error {
	if d == nil || d.Health == nil {
		return fmt.Errorf("app: datastores not connected")
	}
	ready, reports := d.Health.Run(ctx)
	if ready {
		return nil
	}

	names := make([]string, 0, len(reports))
	for _, r := range reports {
		if !r.OK {
			names = append(names, r.Name)
		}
	}
	return fmt.Errorf("app: dependencies unavailable: %v", names)
}
