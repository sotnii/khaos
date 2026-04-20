package api

import (
	"context"
	"fmt"
	"net"

	"github.com/sotnii/pakostii/logging"
	"github.com/sotnii/pakostii/runtime/state"
)

type clusterStateView interface {
	GetNode(nodeID string) *state.NodeState
}

type Cluster struct {
	ctx    context.Context
	state  clusterStateView
	logger logging.Logger
}

func NewCluster(ctx context.Context, state clusterStateView, logger logging.Logger) *Cluster {
	return &Cluster{ctx: ctx, state: state, logger: logger}
}

func (e *Cluster) IpOfNode(nodeID string) (net.IP, error) {
	node := e.state.GetNode(nodeID)
	if node == nil {
		return nil, fmt.Errorf("node %s not found", nodeID)
	}

	ns := node.Namespace()
	if ns == nil {
		return nil, fmt.Errorf("node %s has no network namespace associated", nodeID)
	}

	return ns.AllocatedIP, nil
}
