package api

import (
	"context"
	"fmt"

	"github.com/sotnii/pakostii/containers"
)

type stateReader interface {
	FindContainer(nodeID, containerName string) *containers.RunningContainer
}

type Exec struct {
	ctx     context.Context
	state   stateReader
	manager containers.Manager
}

func NewExec(ctx context.Context, state stateReader, manager containers.Manager) *Exec {
	return &Exec{ctx: ctx, state: state, manager: manager}
}

func (e *Exec) InContainer(nodeID, containerName string, argv []string) (*containers.ExecResult, error) {
	container := e.state.FindContainer(nodeID, containerName)
	if container == nil {
		return nil, fmt.Errorf("container %q on node %q not found", containerName, nodeID)
	}
	return e.manager.ExecInContainer(e.ctx, container.ID, argv)
}
