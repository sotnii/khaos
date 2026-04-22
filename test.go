package pakostii

import (
	"context"
	"log/slog"

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

func (t *Test) Run(ctx context.Context, fn func(*TestHandle) error) error {
	rt, err := t.runtime(t.name, t.clusterSpec, t.logger)
	if err != nil {
		return err
	}
	return rt.Run(ctx, fn)
}
