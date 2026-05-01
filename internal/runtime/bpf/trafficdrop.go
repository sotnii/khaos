package bpf

import (
	"bytes"
	"fmt"
	"net"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sotnii/pakostii/internal/runtime/bpf/assets"
)

type TrafficDrop struct {
	objs trafficDropObjects
}

type TrafficDropHandle struct {
	link link.Link
}

type trafficDropObjects struct {
	Program *ebpf.Program `ebpf:"traffic_drop"` // Note: must be public field so that cillium/ebpf can set it upon LoadAndAssign
}

func NewTrafficDrop() (*TrafficDrop, error) {
	// Load program first.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(assets.XdpPacketDropObject))
	if err != nil {
		return nil, fmt.Errorf("cannot load traffic drop collection spec: %w", err)
	}

	var objs trafficDropObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("cannot load bpf traffic drop objects: %w", err)
	}

	return &TrafficDrop{
		objs: objs,
	}, nil
}

func (d *TrafficDrop) Unload() error {
	return d.objs.Program.Close()
}

func (d *TrafficDrop) Attach(iface *net.Interface) (*TrafficDropHandle, error) {
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   d.objs.Program,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		return nil, fmt.Errorf("attach xdp to %s (ifindex=%d): %w", iface.Name, iface.Index, err)
	}

	return &TrafficDropHandle{
		link: l,
	}, nil
}

func (h *TrafficDropHandle) Close() error {
	return h.link.Close()
}
