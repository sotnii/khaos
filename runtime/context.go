package runtime

import (
	"context"
	"fmt"

	"github.com/sotnii/pakostii/containers"
	"github.com/sotnii/pakostii/runtime/api"
)

type Handle struct {
	ctx     context.Context
	state   *clusterState
	manager containers.Manager
	logger  Logger
}

type Context struct {
	exec *api.Exec
}

func newContext(handle *Handle) *Context {
	return &Context{
		exec: api.NewExec(handle.ctx, handle.state, handle.manager),
	}
}

func (c *Context) Exec() *api.Exec {
	return c.exec
}

func (h *Handle) mustFindContainer(nodeID, containerName string) (*containers.RunningContainer, error) {
	container := h.state.FindContainer(nodeID, containerName)
	if container == nil {
		return nil, fmt.Errorf("container %q on node %q not found", containerName, nodeID)
	}
	return container, nil
}
