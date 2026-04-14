package runtime

import (
	"log/slog"

	"github.com/sotnii/pakostii/spec"
)

type ClusterSpec = spec.ClusterSpec

type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
	With(args ...any) Logger
}

type RuntimeFactory func(name string, cluster *spec.ClusterSpec, logger Logger) (*Runtime, error)

type TestOption func(*Test)

func WithLogger(logger *slog.Logger) TestOption {
	return func(t *Test) {
		if logger != nil {
			t.logger = &slogLogger{logger: logger}
		}
	}
}
