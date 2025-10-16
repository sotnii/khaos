package xdp

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"log"
	"net"
)

type PerfEventType uint8

const (
	TypeEnter PerfEventType = iota + 1
	TypeDrop
	TypePass
)

func (t PerfEventType) String() string {
	switch t {
	case TypeEnter:
		return "Enter"
	case TypeDrop:
		return "Drop"
	case TypePass:
		return "Pass"
	default:
		return "Unknown"
	}
}

type PerfTraceEvent struct {
	TimeSinceBoot  uint64
	ProcessingTime uint32
	Type           PerfEventType
}

func (e PerfTraceEvent) String() string {
	return fmt.Sprintf("PerfTraceEvent{TimeSinceBoot:%d,Type:%v}", e.TimeSinceBoot, e.Type)
}

type PacketDropper struct {
	iface   *net.Interface
	xdpLink link.Link
	objs    *packetDropObjects
}

func NewPacketDropper(iface *net.Interface) PacketDropper {
	return PacketDropper{
		iface: iface,
	}
}

func (pd *PacketDropper) Attach() error {
	// Load the compiled eBPF ELF and load it into the kernel.
	var objs packetDropObjects
	if err := loadPacketDropObjects(&objs, nil); err != nil {
		return err
	}
	pd.objs = &objs

	// Attach count_packets to the network interface.
	xdpLink, err := link.AttachXDP(link.XDPOptions{
		Program:   pd.objs.PacketDrop,
		Interface: pd.iface.Index,
	})
	if err != nil {
		return err
	}
	pd.xdpLink = xdpLink

	return nil
}

func (pd *PacketDropper) Close() error {
	err := pd.objs.Close()
	if err != nil {
		return err
	}
	err = pd.xdpLink.Close()
	if err != nil {
		return err
	}

	return nil
}

func (pd *PacketDropper) TraceEvents(ctx context.Context) (chan PerfTraceEvent, error) {
	eventsCh := make(chan PerfTraceEvent)
	reader, err := perf.NewReader(pd.objs.OutputMap, 4096)
	if err != nil {
		return nil, err
	}

	go func(objs *packetDropObjects) {
		defer func() {
			_ = reader.Close()
			close(eventsCh)
		}()

		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := reader.Read()
				if err != nil {
					log.Printf("reading from perf event reader: %v", err)
					continue
				}

				// Skip lost events
				if record.LostSamples != 0 {
					fmt.Printf("Lost %d samples\n", record.LostSamples)
					continue
				}
				var event PerfTraceEvent
				if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err == nil {
					eventsCh <- event
				}
			}
		}
	}(pd.objs)

	return eventsCh, nil
}
