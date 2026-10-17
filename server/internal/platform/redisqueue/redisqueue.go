// Package redisqueue owns Redis connectivity for the scan job queue.
//
// Phase 1 delivers connection management and health probing only. Enqueue,
// claim and retry arrive in Phase 4.
//
// Two constraints from ADR 0017 govern this package:
//
//   - Redis is required, not optional. It is both the job queue and the
//     rate-limit and quota counter store, and those counters cannot be
//     evaluated without it.
//   - Redis publishes no network port. This package therefore assumes a
//     trusted network peer and has no TLS option; that is a deployment
//     property, not a code default.
package redisqueue

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

// defaultPingTimeout bounds each health probe when none is configured.
const defaultPingTimeout = 3 * time.Second

// Options configures a connection.
type Options struct {
	// Addr is the host:port of the Redis server.
	Addr string
	// Password is optional; the development deployment has none.
	Password string
	// DB selects the logical database.
	DB int
	// PingTimeout bounds each health probe.
	PingTimeout time.Duration
}

// Client is a connected Redis handle.
//
// It satisfies health.Check via Ping. A Client is safe for concurrent use.
type Client struct {
	rdb *redis.Client

	closeOnce sync.Once
}

// Connect opens a connection and verifies the server responds with PONG.
//
// redis.NewClient is lazy — it does not dial until the first command — so the
// ping is issued explicitly. Failing here means a wrong REDIS_ADDR surfaces at
// startup rather than as a silently stalled queue later.
func Connect(ctx context.Context, opts Options) (*Client, error) {
	if opts.Addr == "" {
		return nil, errors.New("redisqueue: Addr is required")
	}
	if opts.PingTimeout <= 0 {
		opts.PingTimeout = defaultPingTimeout
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     opts.Addr,
		Password: opts.Password,
		DB:       opts.DB,
		// -1 means "no read timeout". The default (5s) is shorter than any
		// useful blocking pop, so a BLPOP would abort with an i/o timeout
		// instead of returning when its block elapsed, leaving the connection
		// mid-command.
		//
		// Disabling it is safe because this package never issues a command
		// without a context, and with ContextTimeoutEnabled below the context
		// becomes the deadline. A blocking call with neither would be a hazard,
		// and this API does not permit that shape: every exported method takes
		// a context.Context as its first argument.
		ReadTimeout: -1,

		// With no read timeout the driver's deadline comes from the context
		// instead. That is what lets a blocked consumer wake up on shutdown:
		// without this, go-redis reads with a background context and a
		// cancelled request would sit in BRPOP until its block elapsed.
		ContextTimeoutEnabled: true,
	})

	pingCtx, cancel := context.WithTimeout(ctx, opts.PingTimeout)
	defer cancel()
	if err := rdb.Ping(pingCtx).Err(); err != nil {
		_ = rdb.Close()
		return nil, fmt.Errorf("redisqueue: ping: %w", err)
	}

	return &Client{rdb: rdb}, nil
}

// Redis returns the underlying client.
//
// It is exposed so a component that needs Redis for its own purpose — the
// rate-limit counters, for instance — can share one connection pool instead of
// opening a second one. Reusing the pool keeps connection counts and failure
// modes identical across the process.
func (c *Client) Redis() redis.UniversalClient {
	if c == nil {
		return nil
	}
	return c.rdb
}

// Ping verifies the server responds. It implements health.Check.
func (c *Client) Ping(ctx context.Context) error {
	if c == nil || c.rdb == nil {
		return redis.ErrClosed
	}
	return c.rdb.Ping(ctx).Err()
}

// Close releases the connection pool. It is safe to call more than once.
func (c *Client) Close() error {
	if c == nil || c.rdb == nil {
		return nil
	}

	var err error
	c.closeOnce.Do(func() {
		if closeErr := c.rdb.Close(); closeErr != nil {
			err = fmt.Errorf("redisqueue: close: %w", closeErr)
		}
	})
	return err
}
