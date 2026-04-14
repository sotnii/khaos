package runtime

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorGray   = "\033[90m"
	colorBlue   = "\033[94m"
	colorGreen  = "\033[92m"
	colorYellow = "\033[93m"
	colorRed    = "\033[91m"
	colorBold   = "\033[1m"
)

type colorHandler struct {
	opts   slog.HandlerOptions
	writer io.Writer
	attrs  []slog.Attr
	group  string
	mu     *sync.Mutex
}

func NewLogger(w io.Writer, level slog.Leveler) *slog.Logger {
	if w == nil {
		w = os.Stdout
	}
	if level == nil {
		level = slog.LevelInfo
	}

	return slog.New(&colorHandler{
		opts:   slog.HandlerOptions{Level: level},
		writer: w,
		mu:     &sync.Mutex{},
	})
}

func newDefaultLogger() Logger {
	return NewLogger(os.Stdout, slog.LevelInfo)
}

func NewDiscardLogger() Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{}))
}

func (h *colorHandler) Enabled(_ context.Context, level slog.Level) bool {
	min := slog.LevelInfo
	if h.opts.Level != nil {
		min = h.opts.Level.Level()
	}
	return level >= min
}

func (h *colorHandler) Handle(_ context.Context, record slog.Record) error {
	var b strings.Builder

	ts := record.Time
	if ts.IsZero() {
		ts = time.Now()
	}

	levelText, levelColor := colorizeLevel(record.Level)
	fmt.Fprintf(&b, "%s%s%s ", colorGray, ts.Format("15:04:05.000"), colorReset)
	fmt.Fprintf(&b, "%s%s%-5s%s ", colorBold, levelColor, levelText, colorReset)
	b.WriteString(record.Message)

	attrs := append([]slog.Attr{}, h.attrs...)
	record.Attrs(func(attr slog.Attr) bool {
		attrs = append(attrs, attr)
		return true
	})

	for _, attr := range attrs {
		attr.Value = attr.Value.Resolve()
		key := attr.Key
		if h.group != "" {
			key = h.group + "." + key
		}
		fmt.Fprintf(&b, " %s%s%s=%v", colorBlue, key, colorReset, attr.Value.Any())
	}
	b.WriteByte('\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := io.WriteString(h.writer, b.String())
	return err
}

func (h *colorHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *h
	clone.attrs = append(append([]slog.Attr{}, h.attrs...), attrs...)
	return &clone
}

func (h *colorHandler) WithGroup(name string) slog.Handler {
	clone := *h
	if clone.group == "" {
		clone.group = name
	} else {
		clone.group = clone.group + "." + name
	}
	return &clone
}

func colorizeLevel(level slog.Level) (string, string) {
	switch {
	case level <= slog.LevelDebug:
		return "DEBUG", colorBlue
	case level < slog.LevelWarn:
		return "INFO", colorGreen
	case level < slog.LevelError:
		return "WARN", colorYellow
	default:
		return "ERROR", colorRed
	}
}
