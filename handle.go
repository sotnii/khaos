package pakostii

import (
	"context"
	"log/slog"

	"github.com/sotnii/pakostii/internal/runtime/agent"
	"github.com/sotnii/pakostii/internal/runtime/api"
	"github.com/sotnii/pakostii/internal/runtime/managers"
)

type clusterHandle struct {
	ctx        context.Context
	containers *managers.ContainerManager
	logger     *slog.Logger
	httpAgent  agent.HttpAgent
}

type TestHandle struct {
	exec *api.Exec
	http *api.Http
}

func newTestHandle(handle *clusterHandle) *TestHandle {
	return &TestHandle{
		exec: api.NewExec(handle.ctx, handle.containers, handle.logger.With("component", "exec")),
		http: api.NewHttp(handle.httpAgent),
	}
}

func (c *TestHandle) Exec() *api.Exec {
	return c.exec
}

func (c *TestHandle) Http() *api.Http {
	return c.http
}
