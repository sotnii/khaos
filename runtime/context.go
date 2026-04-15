package runtime

import (
	"context"

	"github.com/sotnii/pakostii/containers"
	"github.com/sotnii/pakostii/logging"
	"github.com/sotnii/pakostii/runtime/api"
	"github.com/sotnii/pakostii/runtime/state"
)

type Handle struct {
	ctx     context.Context
	state   *state.ClusterState
	manager containers.Manager
	logger  logging.Logger
}

type Context struct {
	exec *api.Exec
}

func newContext(handle *Handle) *Context {
	return &Context{
		exec: api.NewExec(handle.ctx, handle.state, handle.manager, handle.logger.With("component", "exec")),
	}
}

func (c *Context) Exec() *api.Exec {
	return c.exec
}
