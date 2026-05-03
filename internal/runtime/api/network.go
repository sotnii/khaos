package api

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/sotnii/pakostii/internal/network"
	"github.com/sotnii/pakostii/internal/runtime/bpf"
	"github.com/sotnii/pakostii/internal/runtime/util"
	"github.com/sotnii/pakostii/spec"
)

type NodeNetworkResolver interface {
	GetNamespace(id spec.NodeID) network.Namespace
}

type Network struct {
	partition *Partition
}

type Partition struct {
	mu              sync.Mutex
	logger          *slog.Logger
	spec            spec.ClusterSpec
	networkResolver NodeNetworkResolver
	handles         []*AZIsolationHandle
}

type AZIsolationHandle struct {
	mu                      sync.Mutex
	name                    string
	logger                  *slog.Logger
	allowedSources          []net.IP
	trafficDrop             *bpf.TrafficDrop
	handles                 []*bpf.TrafficDropHandle
	affectedNamespacesNames []network.Namespace
}

func NewNetwork(spec spec.ClusterSpec, networkResolver NodeNetworkResolver, logger *slog.Logger) *Network {
	return &Network{
		partition: &Partition{
			logger:          logger,
			spec:            spec,
			networkResolver: networkResolver,
			handles:         make([]*AZIsolationHandle, 0),
		},
	}
}

func (n *Network) Partition() *Partition {
	return n.partition
}

func (n *Network) Cleanup() error {
	if n == nil || n.partition == nil {
		return nil
	}
	return n.partition.Cleanup()
}

func (p *Partition) IsolateAZ(name, az string) (*AZIsolationHandle, error) {
	nodes := nodesWithAz(spec.AZID(az), &p.spec)
	namespaces := make([]network.Namespace, len(nodes))
	for i, node := range nodes {
		namespaces[i] = p.networkResolver.GetNamespace(node)
	}

	allowedSources := namespaceIPs(namespaces)

	p.logger.Debug("created isolation handle", "az_isolation", name, "az", az, "ips", allowedSources)

	handle := &AZIsolationHandle{
		logger:                  p.logger.With("az_isolation", name),
		name:                    name,
		allowedSources:          allowedSources,
		handles:                 make([]*bpf.TrafficDropHandle, 0),
		affectedNamespacesNames: namespaces,
	}

	p.mu.Lock()
	p.handles = append(p.handles, handle)
	p.mu.Unlock()

	return handle, nil
}

func (p *Partition) Cleanup() error {
	p.mu.Lock()
	handles := append([]*AZIsolationHandle(nil), p.handles...)
	p.handles = p.handles[:0]
	p.mu.Unlock()

	var errs []error
	for _, handle := range handles {
		if err := handle.Heal(); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (a *AZIsolationHandle) Apply() error {
	a.mu.Lock()

	if len(a.handles) > 0 {
		a.mu.Unlock()
		return fmt.Errorf("isolation handle is already applied, must be healed before reusing")
	}

	if a.trafficDrop == nil {
		td, err := bpf.NewTrafficDrop(a.allowedSources)
		if err != nil {
			a.mu.Unlock()
			return err
		}
		if err := td.StartPacketLogging(a.logger); err != nil {
			unloadErr := td.Unload()
			a.mu.Unlock()
			if unloadErr != nil {
				return errors.Join(err, fmt.Errorf("traffic drop cleanup failed: %w", unloadErr))
			}
			return err
		}
		a.trafficDrop = td
	}

	var errs []error

	a.logger.Debug("applying isolation", "namespaces", a.affectedNamespacesNames)
	for _, ns := range a.affectedNamespacesNames {
		var tdHandle *bpf.TrafficDropHandle
		err := util.WithNetNSPath(ns.Path, func() error {
			iface, err := net.InterfaceByName(ns.Interface)
			a.logger.Debug("resolved interface", "namespace", ns.Path, "interface", ns.Interface)
			if err != nil {
				return fmt.Errorf("failed to find network interface %s in network namespace %s: %w", ns.Interface, ns.Name, err)
			}
			tdHandle, err = a.trafficDrop.Attach(iface, ns.Name)
			if err != nil {
				return fmt.Errorf("failed to attach traffic drop to network namespace %s: %w", ns.Name, err)
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
			break
		}
		a.handles = append(a.handles, tdHandle)
	}

	a.mu.Unlock()

	if len(errs) > 0 {
		healErr := a.Heal()
		if healErr != nil {
			errs = append(errs, fmt.Errorf("applied isolations cleanup failed: %w", healErr))
		}

		return errors.Join(errs...)
	}

	return nil
}

func (a *AZIsolationHandle) Heal() error {
	a.mu.Lock()
	defer a.mu.Unlock()

	if len(a.handles) == 0 {
		if a.trafficDrop == nil {
			return nil
		}
	}

	var errs []error
	a.logger.Debug("closing isolation handles")
	for _, handle := range a.handles {
		err := handle.Close()
		if err != nil {
			errs = append(errs, err)
		}
	}

	a.handles = a.handles[:0]

	if a.trafficDrop != nil {
		err := a.trafficDrop.Unload()
		if err != nil {
			errs = append(errs, err)
		}
		a.trafficDrop = nil
	}

	return errors.Join(errs...)
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

func namespaceIPs(namespaces []network.Namespace) []net.IP {
	ips := make([]net.IP, 0, len(namespaces))
	for _, ns := range namespaces {
		ips = append(ips, ns.AllocatedIP)
	}

	return ips
}
