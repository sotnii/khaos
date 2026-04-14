package runtime

import "context"

type Test struct {
	name        string
	clusterSpec *ClusterSpec
	logger      Logger
	runtime     RuntimeFactory
}

func NewTest(name string, cluster *ClusterSpec, opts ...TestOption) *Test {
	t := &Test{
		name:        name,
		clusterSpec: cluster,
		logger:      newDefaultLogger(),
		runtime:     NewRuntime,
	}
	for _, opt := range opts {
		opt(t)
	}
	return t
}

func (t *Test) Run(ctx context.Context, fn func(*Context) error) error {
	rt, err := t.runtime(t.name, t.clusterSpec, t.logger)
	if err != nil {
		return err
	}
	return rt.Run(ctx, fn)
}
