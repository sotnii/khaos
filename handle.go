package pakostii

import (
	"context"
	"log/slog"

	"github.com/sotnii/pakostii/internal/runtime/agent"
	"github.com/sotnii/pakostii/internal/runtime/api"
	"github.com/sotnii/pakostii/internal/runtime/managers"
	"github.com/sotnii/pakostii/spec"
)

type TestHandle struct {
	Ctx     context.Context
	Logger  *slog.Logger
	exec    *api.Exec
	http    *api.Http
	network *api.Network
}

func newTestHandle(ctx context.Context, spec spec.ClusterSpec, containers *managers.ContainerManager, network *managers.NetworkManager, httpAgent agent.HttpAgent, logger *slog.Logger) *TestHandle {
	return &TestHandle{
		Ctx:     ctx,
		Logger:  logger,
		exec:    api.NewExec(ctx, containers, logger.With("component", "exec_api")),
		http:    api.NewHttp(httpAgent),
		network: api.NewNetwork(spec, network, logger.With("component", "network_api")),
	}
}

func (t *TestHandle) Cleanup() error {
	if t == nil || t.network == nil {
		return nil
	}
	return t.network.Cleanup()
}

func (t *TestHandle) Exec() *api.Exec {
	return t.exec
}

func (t *TestHandle) Http() *api.Http {
	return t.http
}

func (t *TestHandle) Network() *api.Network {
	return t.network
}
