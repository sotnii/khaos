package runtime

import (
	"log/slog"

	"github.com/sotnii/pakostii/logging"
	"github.com/sotnii/pakostii/spec"
)

type ClusterSpec = spec.ClusterSpec

type RuntimeFactory func(name string, cluster *spec.ClusterSpec, logger logging.Logger) (*Runtime, error)

type TestOption func(*Test)

func WithLogger(logger *slog.Logger) TestOption {
	return func(t *Test) {
		if logger != nil {
			t.logger = logger
		}
	}
}
