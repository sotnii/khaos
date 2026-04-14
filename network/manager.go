package network

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

const defaultSubnet = "10.0.0.0/24"

type Namespace struct {
	ID          string
	Name        string
	Path        string
	Interface   string
	BridgePeer  string
	AllocatedIP net.IP
}

type Manager struct {
	prefix     string
	bridgeName string
	ip         *IPCmd
	alloc      *Allocator
}

func NewManager(prefix string, cmd Commander) (*Manager, error) {
	alloc, err := NewAllocator(defaultSubnet)
	if err != nil {
		return nil, err
	}

	return &Manager{
		prefix:     prefix,
		bridgeName: fmt.Sprintf("%s-bridge", prefix),
		ip:         NewIPCmd(cmd),
		alloc:      alloc,
	}, nil
}

func (m *Manager) SetupBridge(ctx context.Context) error {
	exists, up, err := m.ip.LinkStatus(ctx, m.bridgeName)
	if err != nil {
		return fmt.Errorf("check bridge status: %w", err)
	}
	if !exists {
		if err := m.ip.AddBridge(ctx, m.bridgeName); err != nil {
			return fmt.Errorf("create bridge %s: %w", m.bridgeName, err)
		}
	}
	if !up {
		if err := m.ip.BringLinkUp(ctx, m.bridgeName); err != nil {
			return fmt.Errorf("bring bridge %s up: %w", m.bridgeName, err)
		}
	}
	return nil
}

func (m *Manager) CreateNamespace(ctx context.Context, id, logicalName string) (*Namespace, error) {
	name := fmt.Sprintf("%s-%s", m.prefix, logicalName)
	path := filepath.Join("/run/netns", name)

	if _, err := os.Stat(path); err == nil {
		if err := m.ip.DeleteNamespace(ctx, name); err != nil {
			return nil, fmt.Errorf("delete existing namespace %s: %w", name, err)
		}
	}

	if err := m.ip.AddNamespace(ctx, name); err != nil {
		return nil, fmt.Errorf("create namespace %s: %w", name, err)
	}

	return &Namespace{ID: id, Name: name, Path: path}, nil
}

func (m *Manager) SetupNamespace(ctx context.Context, ns *Namespace) error {
	if err := m.ip.NamespaceLinkUp(ctx, ns.Name, "lo"); err != nil {
		return fmt.Errorf("bring loopback up in %s: %w", ns.Name, err)
	}

	veth := fmt.Sprintf("%s-%s-veth", m.prefix, ns.ID)
	bridgePeer := fmt.Sprintf("%s-%s-br", m.prefix, ns.ID)
	if err := m.ip.AddVethPair(ctx, veth, bridgePeer); err != nil {
		return fmt.Errorf("create veth pair for %s: %w", ns.Name, err)
	}
	if err := m.ip.MoveToNamespace(ctx, veth, ns.Name); err != nil {
		return fmt.Errorf("move %s to namespace %s: %w", veth, ns.Name, err)
	}
	if err := m.ip.SetMaster(ctx, bridgePeer, m.bridgeName); err != nil {
		return fmt.Errorf("attach %s to bridge %s: %w", bridgePeer, m.bridgeName, err)
	}
	if err := m.ip.NamespaceLinkUp(ctx, ns.Name, veth); err != nil {
		return fmt.Errorf("bring %s up in namespace %s: %w", veth, ns.Name, err)
	}
	if err := m.ip.BringLinkUp(ctx, bridgePeer); err != nil {
		return fmt.Errorf("bring %s up: %w", bridgePeer, err)
	}

	ip, err := m.alloc.Allocate()
	if err != nil {
		return err
	}
	if err := m.ip.NamespaceAddrAdd(ctx, ns.Name, veth, fmt.Sprintf("%s/%d", ip.String(), m.alloc.Prefix())); err != nil {
		return fmt.Errorf("assign ip to %s: %w", veth, err)
	}

	ns.Interface = veth
	ns.BridgePeer = bridgePeer
	ns.AllocatedIP = ip
	return nil
}

func (m *Manager) TeardownNamespace(ctx context.Context, ns *Namespace) error {
	if ns == nil {
		return nil
	}
	if err := m.ip.DeleteNamespace(ctx, ns.Name); err != nil {
		return fmt.Errorf("delete namespace %s: %w", ns.Name, err)
	}
	return nil
}
