package spec

import "fmt"

type NodeID string
type AZID string

type ClusterSpec struct {
	Name  string
	Nodes []NodeSpec
	AZs   map[AZID]AZSpec
}

type NodeSpec struct {
	ID         NodeID
	Containers []ContainerSpec
	AZ         *AZID
}

type AZSpec struct {
	Nodes []NodeID
}

func NewCluster(name string) *ClusterSpec {
	return &ClusterSpec{
		Name: name,
		AZs:  map[AZID]AZSpec{},
	}
}

func NewNode(id string) NodeSpec {
	return NodeSpec{ID: NodeID(id)}
}

func (s *ClusterSpec) AddNode(node NodeSpec) {
	for _, existing := range s.Nodes {
		if existing.ID == node.ID {
			panic(fmt.Sprintf("node %q already exists", node.ID))
		}
	}
	s.Nodes = append(s.Nodes, node)
}

func (s *ClusterSpec) AddAZ(name string, az AZSpec) AZID {
	key := AZID(name)
	if _, exists := s.AZs[key]; exists {
		panic(fmt.Sprintf("availability zone %q already exists", name))
	}
	s.AZs[key] = az
	return key
}

func (n NodeSpec) WithAZ(az string) NodeSpec {
	value := AZID(az)
	n.AZ = &value
	return n
}

func (n NodeSpec) Runs(containers ...ContainerSpec) NodeSpec {
	n.Containers = append([]ContainerSpec(nil), containers...)
	return n
}

func NewAZ() AZSpec {
	return AZSpec{}
}

func (az AZSpec) WithNode(node string) AZSpec {
	az.Nodes = append(az.Nodes, NodeID(node))
	return az
}
