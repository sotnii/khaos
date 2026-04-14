package api

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/sotnii/pakostii/containers"
)

type clusterStateView interface {
	FindContainer(nodeID, containerName string) *containers.RunningContainer
}

type Exec struct {
	ctx     context.Context
	state   clusterStateView
	manager containers.Manager
	logger  *slog.Logger
}

func NewExec(ctx context.Context, state clusterStateView, manager containers.Manager, logger *slog.Logger) *Exec {
	return &Exec{ctx: ctx, state: state, manager: manager, logger: logger}
}

func (e *Exec) InContainer(nodeID, containerName string, argv ...string) (*containers.ExecResult, error) {
	e.logger.Debug("exec requested", "node", nodeID, "service", containerName, "argv", argv)
	container := e.state.FindContainer(nodeID, containerName)
	if container == nil {
		return nil, fmt.Errorf("container %q on node %q not found", containerName, nodeID)
	}
	res, err := e.manager.ExecInContainer(e.ctx, container.ID, argv)
	if err != nil {
		e.logger.Error("exec failed", "node", nodeID, "service", containerName, "container_id", container.ID, "error", err)
		return nil, err
	}
	e.logger.Debug("exec finished", "node", nodeID, "service", containerName, "container_id", container.ID, "exit_code", res.ExitCode, "stdout_len", len(res.Stdout), "stderr_len", len(res.Stderr))
	return res, nil
}
