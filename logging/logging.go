package logging

import (
	"io"
	"log/slog"
	"os"
)

func NewLogger(w io.Writer, level slog.Leveler) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}
	if level == nil {
		level = slog.LevelInfo
	}

	return slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: level}))
}

func NewDefaultLogger() *slog.Logger {
	return NewLogger(os.Stdout, slog.LevelInfo)
}

func NewDiscardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}
