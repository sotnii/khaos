package api

import (
	"fmt"

	"github.com/sotnii/pakostii/internal/network"
	"github.com/sotnii/pakostii/spec"
)

type NodeNetworkResolver interface {
	GetNamespace(id spec.NodeID) network.Namespace
}

type Network struct {
	partition *Partition
}

func NewNetwork(spec spec.ClusterSpec, networkResolver NodeNetworkResolver) *Network {
	return &Network{
		partition: &Partition{
			spec:            spec,
			networkResolver: networkResolver,
		},
	}
}

func (n *Network) Partition() *Partition {
	return n.partition
}

type Partition struct {
	spec            spec.ClusterSpec
	networkResolver NodeNetworkResolver
}

type AZIsolationHandle struct {
}

func (p *Partition) IsolateAZ(az string) (*AZIsolationHandle, error) {
	nodes := nodesWithAz(spec.AZID(az), &p.spec)
	namespaces := make([]network.Namespace, len(nodes))
	for i, node := range nodes {
		namespaces[i] = p.networkResolver.GetNamespace(node)
	}

	fmt.Println("would isolate", namespaces)

	return &AZIsolationHandle{}, nil
}

func (a *AZIsolationHandle) Heal() {
}

func nodesWithAz(az spec.AZID, cs *spec.ClusterSpec) []spec.NodeID {
	nodes := make([]spec.NodeID, 0)
	for _, node := range cs.Nodes {
		if node.AZ != nil && *node.AZ == az {
			nodes = append(nodes, node.ID)
		}
	}

	return nodes
}
