package runtime

import (
	"context"

	"github.com/sotnii/pakostii/containers"
	"github.com/sotnii/pakostii/logging"
	"github.com/sotnii/pakostii/runtime/agent"
	"github.com/sotnii/pakostii/runtime/api"
	"github.com/sotnii/pakostii/runtime/state"
)

type Handle struct {
	ctx       context.Context
	state     *state.ClusterState
	manager   containers.Manager
	logger    logging.Logger
	httpAgent agent.HttpAgent
}

type Context struct {
	exec    *api.Exec
	cluster *api.Cluster
	http    *api.Http
}

func newContext(handle *Handle) *Context {
	return &Context{
		exec:    api.NewExec(handle.ctx, handle.state, handle.manager, handle.logger.With("component", "exec")),
		cluster: api.NewCluster(handle.ctx, handle.state, handle.logger.With("component", "cluster")),
		http:    api.NewHttp(handle.httpAgent),
	}
}

func (c *Context) Exec() *api.Exec {
	return c.exec
}

func (c *Context) Http() *api.Http {
	return c.http
}

func (c *Context) Cluster() *api.Cluster {
	return c.cluster
}
