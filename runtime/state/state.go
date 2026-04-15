package state

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/sotnii/pakostii/containers"
	"github.com/sotnii/pakostii/network"
	"github.com/sotnii/pakostii/spec"
)

type NodeState struct {
	mu         sync.RWMutex
	resourceID string
	spec       spec.NodeSpec
	namespace  *network.Namespace
	containers map[string]containers.RunningContainer
}

func (ns *NodeState) ResourceID() string {
	return ns.resourceID
}

func (ns *NodeState) Spec() spec.NodeSpec {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	return ns.spec
}

func (ns *NodeState) Namespace() *network.Namespace {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	if ns.namespace == nil {
		return nil
	}
	copied := *ns.namespace
	return &copied
}

func (ns *NodeState) SetNamespace(namespace *network.Namespace) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.namespace = namespace
}

func (ns *NodeState) Containers() map[string]containers.RunningContainer {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	out := make(map[string]containers.RunningContainer, len(ns.containers))
	for k, v := range ns.containers {
		out[k] = v
	}
	return out
}

func (ns *NodeState) AddRunningContainer(containerID string, container containers.RunningContainer) {
	ns.mu.Lock()
	defer ns.mu.Unlock()
	ns.containers[containerID] = container
}

func (ns *NodeState) FindContainerByName(containerName string) *containers.RunningContainer {
	ns.mu.RLock()
	defer ns.mu.RUnlock()
	for _, candidate := range ns.containers {
		if candidate.Name == containerName {
			return &candidate
		}
	}
	return nil
}

type ClusterState struct {
	mu             sync.RWMutex
	testID         string
	nodes          []*NodeState
	agentNamespace *network.Namespace
}

func NewClusterState(cluster *spec.ClusterSpec) *ClusterState {
	nodes := make([]*NodeState, 0, len(cluster.Nodes))
	for _, node := range cluster.Nodes {
		nodes = append(nodes, &NodeState{
			resourceID: NewResourceID(),
			spec:       node,
			containers: map[string]containers.RunningContainer{},
		})
	}

	return &ClusterState{
		testID: NewResourceID(),
		nodes:  nodes,
	}
}

func (s *ClusterState) TestID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.testID
}

func (s *ClusterState) Nodes() []*NodeState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*NodeState, len(s.nodes))
	copy(out, s.nodes)
	return out
}

func (s *ClusterState) withWrite(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

func (s *ClusterState) SetAgentNamespace(ns *network.Namespace) {
	s.withWrite(func() {
		s.agentNamespace = ns
	})
}

func (s *ClusterState) FindContainer(nodeID, containerName string) *containers.RunningContainer {
	s.mu.RLock()
	nodes := make([]*NodeState, len(s.nodes))
	copy(nodes, s.nodes)
	s.mu.RUnlock()

	for _, node := range nodes {
		if node.Spec().ID != spec.NodeID(nodeID) {
			continue
		}
		if found := node.FindContainerByName(containerName); found != nil {
			return found
		}
	}

	return nil
}

func (s *ClusterState) AgentNamespace() *network.Namespace {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.agentNamespace == nil {
		return nil
	}
	copied := *s.agentNamespace
	return &copied
}

func (s *ClusterState) DrainNodes() []*NodeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.nodes
	s.nodes = nil
	return out
}

func NewResourceID() string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz"
	var bytes [5]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(fmt.Sprintf("read random bytes: %v", err))
	}

	out := make([]byte, len(bytes))
	for i, b := range bytes {
		out[i] = alphabet[int(b)%len(alphabet)]
	}
	return string(out)
}
