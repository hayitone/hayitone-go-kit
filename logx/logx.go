// Package logx builds the service's structured logger: JSON lines on stdout, one shape for
// every service, so logs from the gateway and every service can be searched the same way.
package logx

import (
	"io"
	"log/slog"
	"strings"
)

// New returns a JSON logger that tags every line with the service and environment.
func New(w io.Writer, level, service, env string) *slog.Logger {
	var l slog.Level
	switch strings.ToLower(level) {
	case "debug":
		l = slog.LevelDebug
	case "warn":
		l = slog.LevelWarn
	case "error":
		l = slog.LevelError
	default:
		l = slog.LevelInfo
	}
	h := slog.NewJSONHandler(w, &slog.HandlerOptions{Level: l})
	return slog.New(h).With("service", service, "env", env)
}
