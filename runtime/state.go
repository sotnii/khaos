package runtime

import (
	"crypto/rand"
	"fmt"
	"sync"

	"github.com/sotnii/pakostii/containers"
	"github.com/sotnii/pakostii/network"
	"github.com/sotnii/pakostii/spec"
)

type containerState struct {
	running *containers.RunningContainer
}

type nodeState struct {
	resourceID string
	spec       spec.NodeSpec
	namespace  *network.Namespace
	containers map[string]*containerState
}

type clusterState struct {
	mu             sync.RWMutex
	testID         string
	nodes          []*nodeState
	agentNamespace *network.Namespace
}

func newClusterState(cluster *spec.ClusterSpec) *clusterState {
	nodes := make([]*nodeState, 0, len(cluster.Nodes))
	for _, node := range cluster.Nodes {
		nodes = append(nodes, &nodeState{
			resourceID: newResourceID(),
			spec:       node,
			containers: map[string]*containerState{},
		})
	}

	return &clusterState{
		testID: newResourceID(),
		nodes:  nodes,
	}
}

func (s *clusterState) TestID() string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.testID
}

func (s *clusterState) Nodes() []*nodeState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*nodeState, len(s.nodes))
	copy(out, s.nodes)
	return out
}

func (s *clusterState) WithWrite(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

func (s *clusterState) FindContainer(nodeID, containerName string) *containers.RunningContainer {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, node := range s.nodes {
		if string(node.spec.ID) != nodeID {
			continue
		}
		for _, candidate := range node.containers {
			if candidate.running != nil && candidate.running.Name == containerName {
				return candidate.running
			}
		}
	}

	return nil
}

func (s *clusterState) AgentNamespace() *network.Namespace {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.agentNamespace
}

func (s *clusterState) drainNodes() []*nodeState {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.nodes
	s.nodes = nil
	return out
}

func newResourceID() string {
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
