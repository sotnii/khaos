package api

import (
	"context"
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
	ctx             context.Context
	logger          *slog.Logger
	spec            spec.ClusterSpec
	networkResolver NodeNetworkResolver

	td *bpf.TrafficDrop
}

type AZIsolationHandle struct {
	mu                      sync.Mutex
	logger                  *slog.Logger
	trafficDrop             *bpf.TrafficDrop
	handles                 []*bpf.TrafficDropHandle
	affectedNamespacesNames []network.Namespace
}

func NewNetwork(ctx context.Context, spec spec.ClusterSpec, networkResolver NodeNetworkResolver, logger *slog.Logger) *Network {
	return &Network{
		partition: &Partition{
			logger:          logger,
			ctx:             ctx,
			spec:            spec,
			networkResolver: networkResolver,
		},
	}
}

func (n *Network) Partition() *Partition {
	return n.partition
}

func (p *Partition) trafficDrop() (*bpf.TrafficDrop, error) {
	if p.td == nil {
		td, err := bpf.NewTrafficDrop()
		if err != nil {
			return nil, err
		}
		p.td = td

		go func() {
			<-p.ctx.Done()
			p.logger.Debug("unloading traffic drop after context cancellation")
			err := p.td.Unload()
			if err != nil {
				p.logger.Error("failed to unload traffic drop bpf", "error", err)
			}
		}()
	}

	return p.td, nil
}

func (p *Partition) IsolateAZ(az string) (*AZIsolationHandle, error) {
	nodes := nodesWithAz(spec.AZID(az), &p.spec)
	namespaces := make([]network.Namespace, len(nodes))
	for i, node := range nodes {
		namespaces[i] = p.networkResolver.GetNamespace(node)
	}

	p.logger.Debug("created isolation handle", "az", az)

	td, err := p.trafficDrop()
	if err != nil {
		return nil, err
	}
	handle := &AZIsolationHandle{
		logger:                  p.logger.With("isolation", az),
		trafficDrop:             td,
		handles:                 make([]*bpf.TrafficDropHandle, 0),
		affectedNamespacesNames: namespaces,
	}

	go func() {
		<-p.ctx.Done()
		p.logger.Debug("automatically healing isolation handle after context cancellation")
		err := handle.Heal()
		if err != nil {
			p.logger.Error("failed to heal isolation handle after context was cancelled", "error", err)
		}
	}()

	return handle, nil
}

func (a *AZIsolationHandle) Apply() error {
	a.mu.Lock()

	if len(a.handles) > 0 {
		return fmt.Errorf("isolation handle is already applied, must be healed before reusing")
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
			tdHandle, err = a.trafficDrop.Attach(iface)
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
		return nil
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
