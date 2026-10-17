// Package mongostore owns MongoDB connectivity.
//
// This package is deliberately limited to connection management, bounded
// timeouts and health probing. It contains no query logic: the assessment,
// transient-URL and ruleset collections arrive in Phase 3, and keeping them out
// now means the connection semantics can be proven in isolation.
//
// MongoDB is the authoritative store — see docs/architecture/CYBERGUARD_PROJECT.md
// section 7 and ADR 0002. Nothing here is allowed to store a raw URL.
package mongostore

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

// ErrClosed is returned by operations on a Store that has been disconnected.
var ErrClosed = errors.New("mongostore: store is closed")

// Options configures a connection.
type Options struct {
	// URI is the MongoDB connection string. It may contain credentials, so it
	// is never logged by this package.
	URI string
	// Database is the logical database name.
	Database string
	// ConnectTimeout bounds the initial connection and server selection.
	ConnectTimeout time.Duration
	// PingTimeout bounds each health probe.
	PingTimeout time.Duration
}

// Store is a connected MongoDB handle.
//
// It satisfies health.Check via Ping. A Store is safe for concurrent use by
// multiple goroutines once returned by Connect.
type Store struct {
	client *mongo.Client
	db     *mongo.Database

	closeOnce sync.Once
}

// Connect opens a connection and verifies the deployment is reachable.
//
// It fails if the server is unreachable rather than returning a Store that
// only breaks later, so a misconfigured MONGODB_URI fails at startup instead of
// surfacing as a confusing runtime error.
//
// The MongoDB driver's Connect does not accept a context and does not validate
// reachability, so the ping is performed explicitly here.
func Connect(ctx context.Context, opts Options) (*Store, error) {
	if opts.URI == "" {
		return nil, errors.New("mongostore: URI is required")
	}
	if opts.Database == "" {
		return nil, errors.New("mongostore: Database is required")
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
		return nil, fmt.Errorf("mongostore: connect: %w", err)
	}

	pingCtx, cancel := context.WithTimeout(ctx, opts.PingTimeout)
	defer cancel()
	if err := client.Ping(pingCtx, readpref.Primary()); err != nil {
		// Release the driver's monitoring goroutines before giving up, or a
		// process that retries Connect would leak a topology per attempt.
		_ = client.Disconnect(context.Background())
		return nil, fmt.Errorf("mongostore: ping: %w", err)
	}

	return &Store{client: client, db: client.Database(opts.Database)}, nil
}

// Ping verifies the deployment is reachable. It implements health.Check.
func (s *Store) Ping(ctx context.Context) error {
	if s == nil || s.client == nil {
		return ErrClosed
	}
	return s.client.Ping(ctx, readpref.Primary())
}

// Database returns the configured database handle.
func (s *Store) Database() *mongo.Database {
	if s == nil {
		return nil
	}
	return s.db
}

// Disconnect closes the connection pool and stops the driver's background
// goroutines. It is safe to call more than once, so deferred cleanup and an
// explicit shutdown path can both call it.
func (s *Store) Disconnect(ctx context.Context) error {
	if s == nil || s.client == nil {
		return nil
	}

	var err error
	s.closeOnce.Do(func() {
		if disconnectErr := s.client.Disconnect(ctx); disconnectErr != nil {
			err = fmt.Errorf("mongostore: disconnect: %w", disconnectErr)
		}
	})
	return err
}
