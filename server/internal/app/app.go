// Package app holds dependency wiring shared by the api and worker binaries.
//
// Both processes need the same three things: a MongoDB connection, a Redis
// connection, and a health checker over both. Keeping that in one place stops
// the two mains from drifting, which is the usual failure mode of duplicated
// setup code — one binary learns to time out and the other does not.
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
	"cyberguard/server/internal/platform/redisqueue"
)

// Datastores is the set of external dependencies both binaries hold open.
type Datastores struct {
	Mongo  *mongostore.Store
	Redis  *redisqueue.Client
	Health *health.Checker
}

// ConnectDatastores opens the MongoDB and Redis connections and builds the
// readiness checker over them.
//
// It fails fast: a wrong MONGODB_URI or REDIS_ADDR returns an error rather than
// a half-working process. Docker Compose already gates startup on both
// services reporting healthy, so in practice this surfaces genuine
// misconfiguration.
//
// On partial failure any already-open connection is closed before returning,
// so a failed start leaks no sockets or driver goroutines.
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

	redisConn, err := redisqueue.Connect(ctx, redisqueue.Options{
		Addr:        cfg.RedisAddr,
		Password:    cfg.RedisPassword,
		DB:          cfg.RedisDB,
		PingTimeout: cfg.RedisPingTimeout,
	})
	if err != nil {
		_ = mongo.Disconnect(context.WithoutCancel(ctx))
		return nil, err
	}
	logger.Info("redis connected", slog.String("addr", cfg.RedisAddr))

	return &Datastores{
		Mongo: mongo,
		Redis: redisConn,
		Health: health.NewChecker(cfg.HealthCheckTimeout,
			health.Named{Name: "mongodb", Check: mongo},
			health.Named{Name: "redis", Check: redisConn},
		),
	}, nil
}

// Close releases both connections. It always attempts both, and joins the
// errors, so one failure does not strand the other's sockets.
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
	if d.Redis != nil {
		if err := d.Redis.Close(); err != nil {
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
