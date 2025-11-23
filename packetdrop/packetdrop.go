package packetdrop

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
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
	Type  PerfEventType
	SrcIP uint32
	// TODO: Src port reads as garbage
	SrcPort uint16
}

func (e PerfTraceEvent) String() string {
	ipBytes := make([]byte, 4)
	binary.NativeEndian.PutUint32(ipBytes, e.SrcIP)
	ipAddress := net.IP(ipBytes)

	return fmt.Sprintf("[%s]: from %s:%d", e.Type, ipAddress, e.SrcPort)
}

type PacketDropper struct {
	iface      *net.Interface
	targetIP   net.IP
	targetPort uint16
	dropPct    uint32
	xdpLink    link.Link
	objs       *packetDropObjects
}

func NewPacketDropper(iface *net.Interface, ip net.IP, targetPort int, dropPct int) (PacketDropper, error) {
	if ip == nil {
		return PacketDropper{}, errors.New("must provide IP addr")
	}

	return PacketDropper{
		iface:      iface,
		targetIP:   ip,
		targetPort: uint16(targetPort),
		dropPct:    uint32(dropPct),
	}, nil
}

func (pd *PacketDropper) Attach() error {
	// Load the object file from disk using a bpf2go-generated scaffolding.
	spec, err := loadPacketDrop()
	if err != nil {
		return err
	}

	ipVal := net.IPv4zero
	if pd.targetIP != nil {
		ipVal = pd.targetIP
	}
	if err := spec.Variables["target_src_ip"].Set(ipVal.To4()); err != nil {
		return err
	}

	if err := spec.Variables["target_src_port"].Set(pd.targetPort); err != nil {
		return err
	}
	if err := spec.Variables["drop_pct"].Set(pd.dropPct); err != nil {
		return err
	}

	// Note: modifying spec.Variables after this point is ineffectual!
	// Modifying *Spec resources does not affect loaded/running BPF programs.
	var objs packetDropObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
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
	recordCh := make(chan perf.Record)
	reader, err := perf.NewReader(pd.objs.OutputMap, 4096)
	if err != nil {
		return nil, err
	}

	go func() {
		for ctx.Err() == nil {
			record, err := reader.Read()
			if err != nil && !errors.Is(err, perf.ErrClosed) {
				log.Printf("reading from perf event reader: %v", err)
				continue
			}

			// Skip lost events
			if record.LostSamples != 0 {
				fmt.Printf("Lost %d samples\n", record.LostSamples)
				continue
			}
			recordCh <- record
		}
	}()

	go func(objs *packetDropObjects) {
		ticker := time.NewTicker(1 * time.Second)
		defer ticker.Stop()
		defer func() {
			_ = reader.Close()
			close(eventsCh)
		}()

		for {
			select {
			case <-ctx.Done():
				return
			case record := <-recordCh:
				var event PerfTraceEvent
				if err = binary.Read(bytes.NewBuffer(record.RawSample), binary.NativeEndian, &event); err == nil {
					eventsCh <- event
				}
			case <-ticker.C:
				continue
			}
		}
	}(pd.objs)

	return eventsCh, nil
}
