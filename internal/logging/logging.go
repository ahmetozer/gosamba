// Package logging configures slog handlers per gosamba's config.
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
)

// New returns an *slog.Logger writing to w (typically os.Stderr).
func New(w io.Writer, level, format string) (*slog.Logger, error) {
	if w == nil {
		w = os.Stderr
	}
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "info":
		lvl = slog.LevelInfo
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		return nil, fmt.Errorf("invalid log level %q", level)
	}
	opts := &slog.HandlerOptions{Level: lvl}
	var h slog.Handler
	switch format {
	case "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return nil, fmt.Errorf("invalid log format %q", format)
	}
	return slog.New(h), nil
}
