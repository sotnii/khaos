package provision

import (
	"context"
	"fmt"

	"github.com/sotnii/pakostii/logging"
	"github.com/sotnii/pakostii/network"
	"github.com/sotnii/pakostii/runtime/state"
)

type NetworkProvisioner struct {
	manager *network.Manager
	logger  logging.Logger
}

func NewNetworkProvisioner(manager *network.Manager, logger logging.Logger) *NetworkProvisioner {
	return &NetworkProvisioner{
		manager: manager,
		logger:  logger.With("component", "network_provisioner"),
	}
}

func (p *NetworkProvisioner) Provision(ctx context.Context, cs *state.ClusterState) error {
	p.logger.Info("provisioning network")
	if err := p.manager.SetupBridge(ctx); err != nil {
		return err
	}

	agentNS, err := p.manager.CreateNamespace(ctx, state.NewResourceID(), "agent")
	if err != nil {
		return err
	}
	if err := p.manager.SetupNamespace(ctx, agentNS); err != nil {
		return err
	}
	p.logger.Debug("agent namespace ready", "namespace", agentNS.Name, "path", agentNS.Path)

	cs.SetAgentNamespace(agentNS)

	for _, node := range cs.Nodes() {
		nodeSpec := node.Spec()
		p.logger.Debug("provisioning node namespace", "node", nodeSpec.ID, "resource_id", node.ResourceID())
		ns, err := p.manager.CreateNamespace(ctx, node.ResourceID(), fmt.Sprintf("node-%s", node.ResourceID()))
		if err != nil {
			return err
		}
		if err := p.manager.SetupNamespace(ctx, ns); err != nil {
			return err
		}

		node.SetNamespace(ns)
	}

	return nil
}
