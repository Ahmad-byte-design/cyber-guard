package redisqueue

import (
	"strings"
	"testing"
	"time"
)

func TestConnectRejectsMissingAddr(t *testing.T) {
	t.Parallel()

	for _, addr := range []string{"", "   "} {
		if _, err := Connect(t.Context(), Options{Addr: addr}); err == nil {
			t.Errorf("Connect with Addr=%q succeeded, want an error", addr)
		}
	}
}

// redis.NewClient is lazy, so Connect pings explicitly. An unreachable server
// must therefore fail here rather than leaving a silently stalled queue.
func TestConnectFailsWhenServerIsUnreachable(t *testing.T) {
	t.Parallel()

	// Port 1 on loopback is reserved and refuses immediately.
	_, err := Connect(t.Context(), Options{
		Addr:        "127.0.0.1:1",
		PingTimeout: 200 * time.Millisecond,
	})
	if err == nil {
		t.Fatal("Connect to an unreachable server succeeded, want an error")
	}
	if !strings.Contains(err.Error(), "redisqueue") {
		t.Errorf("error = %q, want it prefixed with the package name", err)
	}
}

// Methods must be safe on a nil or already-closed client, because both shutdown
// paths close the datastores.
func TestNilAndClosedClientAreSafe(t *testing.T) {
	t.Parallel()

	var nilClient *Client
	if err := nilClient.Ping(t.Context()); err == nil {
		t.Error("Ping on a nil Client returned nil, want an error")
	}
	if err := nilClient.Close(); err != nil {
		t.Errorf("Close on a nil Client = %v, want nil", err)
	}

	empty := &Client{}
	if err := empty.Ping(t.Context()); err == nil {
		t.Error("Ping on an unconnected Client returned nil, want an error")
	}
	if err := empty.Close(); err != nil {
		t.Errorf("Close on an unconnected Client = %v, want nil", err)
	}
}

func TestCloseIsIdempotent(t *testing.T) {
	t.Parallel()

	client := &Client{}
	for i := 0; i < 3; i++ {
		if err := client.Close(); err != nil {
			t.Fatalf("Close call %d = %v, want nil", i+1, err)
		}
	}
}
