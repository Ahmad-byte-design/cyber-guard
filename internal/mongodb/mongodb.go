// Package mongodb owns the MongoDB connection and the one collection this
// service persists to.
//
// Connectivity and queries are separated: Connect verifies reachability before
// declaring the process usable, and the Store holds the only query logic.
package mongodb

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
	"go.mongodb.org/mongo-driver/v2/mongo/readpref"
)

// Defaults applied when an Options field is zero.
const (
	defaultConnectTimeout = 10 * time.Second
	defaultPingTimeout    = 5 * time.Second
)

// Options configures a connection.
type Options struct {
	// URI is the MongoDB connection string. It may contain credentials, so
	// it is never logged by this package.
	URI string
	// Database is the logical database name.
	Database string
	// ConnectTimeout bounds the initial connection and server selection.
	ConnectTimeout time.Duration
	// PingTimeout bounds each health probe.
	PingTimeout time.Duration
}

// DB is a connected MongoDB handle. It is safe for concurrent use.
type DB struct {
	client *mongo.Client
	db     *mongo.Database

	closeOnce sync.Once
}

// Connect opens the connection and verifies the deployment is reachable.
//
// It fails rather than returning a handle that only breaks later, so a wrong
// MONGODB_URI is a startup error, not a confusing runtime one. The driver's
// Connect does not contact the server, so the ping is performed explicitly.
func Connect(ctx context.Context, opts Options) (*DB, error) {
	if opts.URI == "" {
		return nil, errors.New("mongodb: URI is required")
	}
	if opts.Database == "" {
		return nil, errors.New("mongodb: Database is required")
	}
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = defaultConnectTimeout
	}
	if opts.PingTimeout <= 0 {
		opts.PingTimeout = defaultPingTimeout
	}

	clientOpts := options.Client().
		ApplyURI(opts.URI).
		SetConnectTimeout(opts.ConnectTimeout).
		SetServerSelectionTimeout(opts.PingTimeout).
		SetAppName("cyberguard")

	client, err := mongo.Connect(clientOpts)
	if err != nil {
		return nil, fmt.Errorf("mongodb: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, opts.PingTimeout)
	defer cancel()
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		// Release the driver's monitoring goroutines before giving up, or a
		// process that retries Connect leaks a topology per attempt.
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("mongodb: ping: %w", err)
	}

	return &DB{client: client, db: client.Database(opts.Database)}, nil
}

// Ping verifies the deployment is reachable.
func (d *DB) Ping(ctx context.Context) error {
	if d == nil || d.client == nil {
		return errors.New("mongodb: not connected")
	}
	return d.client.Ping(ctx, readpref.Primary())
}

// Database returns the configured database handle.
func (d *DB) Database() *mongo.Database {
	if d == nil {
		return nil
	}
	return d.db
}

// Disconnect closes the connection pool. It is safe to call more than once,
// so deferred cleanup and an explicit shutdown path can both call it.
func (d *DB) Disconnect(ctx context.Context) error {
	if d == nil || d.client == nil {
		return nil
	}
	var err error
	d.closeOnce.Do(func() {
		if disconnectErr := d.client.Disconnect(ctx); disconnectErr != nil {
			err = fmt.Errorf("mongodb: disconnect: %w", disconnectErr)
		}
	})
	return err
}
