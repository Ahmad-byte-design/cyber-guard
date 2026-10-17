package mongostore

import (
	"strings"
	"testing"
	"time"
)

// A wrong or missing URI must fail at startup, not surface later as a
// confusing runtime error.
func TestConnectRejectsIncompleteConfiguration(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		opts Options
	}{
		{"no URI", Options{Database: "db"}},
		{"blank URI", Options{URI: "   ", Database: "db"}},
		{"no database", Options{URI: "mongodb://localhost:27017"}},
		{"blank database", Options{URI: "mongodb://localhost:27017", Database: " "}},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := Connect(t.Context(), tc.opts); err == nil {
				t.Fatal("Connect succeeded with incomplete options, want an error")
			}
		})
	}
}

// Connect pings, so an unreachable server is an error rather than a handle that
// only fails later. The timeout is kept short so the unit suite stays fast.
func TestConnectFailsWhenServerIsUnreachable(t *testing.T) {
	t.Parallel()

	// Port 1 on loopback is reserved and refuses immediately.
	_, err := Connect(t.Context(), Options{
		URI:            "mongodb://127.0.0.1:1",
		Database:       "cyberguard",
		ConnectTimeout: 200 * time.Millisecond,
		PingTimeout:    200 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Connect to an unreachable server succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "mongostore") {
		t.Errorf("error = %q, want it prefixed with the package name", err)
	}
}

// Methods must be safe on a nil or already-disconnected store, because the API
// closes datastores on both the success and the failure shutdown paths.
func TestNilAndClosedStoreAreSafe(t *testing.T) {
	t.Parallel()

	var nilStore *Store
	if err := nilStore.Ping(t.Context()); err == nil {
		t.Error("Ping on a nil Store returned nil, want an error")
	}
	if got := nilStore.Database(); got != nil {
		t.Errorf("Database on a nil Store = %v, want nil", got)
	}
	if err := nilStore.Disconnect(t.Context()); err != nil {
		t.Errorf("Disconnect on a nil Store = %v, want nil", err)
	}

	// A Store constructed without Connect has a nil client.
	empty := &Store{}
	if err := empty.Ping(t.Context()); err == nil {
		t.Error("Ping on an unconnected Store returned nil, want an error")
	}
	if err := empty.Disconnect(t.Context()); err != nil {
		t.Errorf("Disconnect on an unconnected Store = %v, want nil", err)
	}
}

// Disconnect is documented as idempotent so deferred and explicit cleanup can
// both call it.
func TestDisconnectIsIdempotent(t *testing.T) {
	t.Parallel()

	store := &Store{}
	for i := 0; i < 3; i++ {
		if err := store.Disconnect(t.Context()); err != nil {
			t.Fatalf("Disconnect call %d = %v, want nil", i+1, err)
		}
	}
}
