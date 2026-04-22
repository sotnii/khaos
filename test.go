package pakostii

import (
	"context"
	"log/slog"
	"os"

	"github.com/sotnii/pakostii/logging"
)

type Test struct {
	name        string
	clusterSpec ClusterSpec
	logger      *slog.Logger
	runtime     RuntimeFactory
}

func NewTest(name string, cluster *ClusterSpec, opts ...TestOption) *Test {
	if cluster == nil {
		panic("cluster spec cannot be nil")
	}
	t := &Test{
		name:        name,
		clusterSpec: *cluster,
		logger:      logging.NewDefaultLogger(),
		runtime:     NewTestRuntime,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

func (t *Test) Run(ctx context.Context, fn func(*TestHandle) error) {
	logger := t.logger.With("test", t.name)
	rt, err := t.runtime(t.name, t.clusterSpec, logger)
	if err != nil {
		logger.Error("error creating runtime", "error", err)
		os.Exit(1)
	}
	err = rt.Run(ctx, fn)
	if err != nil {
		logger.Error("test failed", "error", err)
		os.Exit(1)
	}
	logger.Info("test passed")
}
