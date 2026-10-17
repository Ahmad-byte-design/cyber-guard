// Package logging builds the structured logger used by the API and worker.
//
// Output is JSON by default so containers can be aggregated without regex
// parsing. Callers are responsible for never passing raw URLs or secrets as
// attribute values; this package does not attempt to scrub them, because
// silently mutating a log field hides bugs.
package logging

import (
	"io"
	"log/slog"
	"os"
	"strings"
)

// New returns a logger writing to w.
func New(w io.Writer, level, format string) *slog.Logger {
	opts := &slog.HandlerOptions{Level: parseLevel(level)}

	var h slog.Handler
	if strings.EqualFold(format, "text") {
		h = slog.NewTextHandler(w, opts)
	} else {
		h = slog.NewJSONHandler(w, opts)
	}

	// Replace the default source-tracking attributes with a service tag so
	// logs from the api and worker are distinguishable in a shared stream.
	return slog.New(h).With(slog.String("service", "cyberguard"))
}

// Default writes to stderr, which is what Docker captures.
func Default(level, format string) *slog.Logger {
	return New(os.Stderr, level, format)
}

func parseLevel(level string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
