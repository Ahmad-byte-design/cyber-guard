//go:build integration

// Integration tests for MongoDB connectivity.
//
// Run against the Compose stack:
//
//	docker compose up -d mongodb
//	docker compose run --rm go go test -tags integration ./internal/platform/mongostore/...
//
// The tag keeps these out of `go test ./...` so the default suite stays fast and
// dependency-free.
//
// What lives here is connection semantics — connect, ping, database handle,
// idempotent disconnect. Query behaviour and index enforcement belong to Phase 3,
// and index guarantees in particular must be tested against a real server rather
// than a mock, because the unique index on url_fingerprint is the correctness
// guarantee behind job deduplication.
package mongostore_test

import (
	"context"
	"os"
	"testing"
	"time"

	"cyberguard/server/internal/platform/mongostore"
)

func uri(t *testing.T) string {
	t.Helper()
	v := os.Getenv("MONGODB_URI")
	if v == "" {
		v = "mongodb://mongodb:27017" // Compose service name
	}
	return v
}

func database(t *testing.T) string {
	t.Helper()
	v := os.Getenv("MONGODB_DATABASE")
	if v == "" {
		v = "cyberguard_integration"
	}
	return v
}

func connect(t *testing.T) *mongostore.Store {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	store, err := mongostore.Connect(ctx, mongostore.Options{
		URI:            uri(t),
		Database:       database(t),
		ConnectTimeout: 10 * time.Second,
		PingTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() {
		closeCtx, closeCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer closeCancel()
		if err := store.Disconnect(closeCtx); err != nil {
			t.Errorf("Disconnect: %v", err)
		}
	})
	return store
}

func TestConnectPingsReachableServer(t *testing.T) {
	store := connect(t)

	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()

	if err := store.Ping(ctx); err != nil {
		t.Fatalf("Ping against a running MongoDB: %v", err)
	}
}

func TestDatabaseHandleIsConfigured(t *testing.T) {
	store := connect(t)

	db := store.Database()
	if db == nil {
		t.Fatal("Database returned nil")
	}
	if got := db.Name(); got != database(t) {
		t.Errorf("Database().Name() = %q, want %q", got, database(t))
	}
}

// Disconnect must be safe to call twice: the API closes datastores on both the
// clean-shutdown and the listen-error paths.
func TestDisconnectIsIdempotentAgainstRealServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	store, err := mongostore.Connect(ctx, mongostore.Options{
		URI:            uri(t),
		Database:       database(t),
		ConnectTimeout: 10 * time.Second,
		PingTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if err := store.Disconnect(ctx); err != nil {
		t.Fatalf("first Disconnect: %v", err)
	}
	if err := store.Disconnect(ctx); err != nil {
		t.Fatalf("second Disconnect: %v, want nil", err)
	}
}

// After Disconnect the driver is closed, so Ping must fail rather than
// silently succeed — which would make readiness lie.
func TestPingFailsAfterDisconnect(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()

	store, err := mongostore.Connect(ctx, mongostore.Options{
		URI:            uri(t),
		Database:       database(t),
		ConnectTimeout: 10 * time.Second,
		PingTimeout:    5 * time.Second,
	})
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}

	if err := store.Disconnect(ctx); err != nil {
		t.Fatalf("Disconnect: %v", err)
	}

	pingCtx, pingCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer pingCancel()
	if err := store.Ping(pingCtx); err == nil {
		t.Error("Ping succeeded after Disconnect, want an error")
	}
}
