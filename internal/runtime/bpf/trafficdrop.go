package bpf

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/sotnii/pakostii/internal/runtime/bpf/assets"
)

type TrafficDrop struct {
	objs            trafficDropObjects
	packetLogReader *ringbuf.Reader
	packetLogDone   chan struct{}
	packetLogMu     sync.Mutex
	namespacesMu    sync.RWMutex
	namespaces      map[uint32]string
}

type TrafficDropHandle struct {
	link        link.Link
	trafficDrop *TrafficDrop
	ifindex     uint32
}

type trafficDropObjects struct {
	Program        *ebpf.Program `ebpf:"traffic_drop"`    // Note: must be public field so that cillium/ebpf can set it upon LoadAndAssign
	AllowedSources *ebpf.Map     `ebpf:"ALLOWED_SOURCES"` // Note: must be public field so that cillium/ebpf can set it upon LoadAndAssign
	PacketLogs     *ebpf.Map     `ebpf:"PACKET_LOGS"`     // Note: must be public field so that cillium/ebpf can set it upon LoadAndAssign
}

const (
	packetDecisionPass = uint8(1)
	packetDecisionDrop = uint8(2)
	packetLogSize      = 16
)

func NewTrafficDrop(allowedSources []net.IP) (*TrafficDrop, error) {
	// Load program first.
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(assets.XdpPacketDropObject))
	if err != nil {
		return nil, fmt.Errorf("cannot load traffic drop collection spec: %w", err)
	}

	var objs trafficDropObjects
	if err := spec.LoadAndAssign(&objs, nil); err != nil {
		return nil, fmt.Errorf("cannot load bpf traffic drop objects: %w", err)
	}

	for _, ip := range allowedSources {
		ipv4 := ip.To4()
		if ipv4 == nil {
			_ = unloadTrafficDropObjects(objs)
			return nil, fmt.Errorf("traffic drop allowed source %s is not an IPv4 address", ip)
		}

		var key [4]byte
		copy(key[:], ipv4)
		value := uint8(1)
		if err := objs.AllowedSources.Put(key, value); err != nil {
			_ = unloadTrafficDropObjects(objs)
			return nil, fmt.Errorf("populate traffic drop allowed source %s: %w", ip, err)
		}
	}

	return &TrafficDrop{
		objs:       objs,
		namespaces: make(map[uint32]string),
	}, nil
}

func (d *TrafficDrop) Unload() error {
	d.stopPacketLogging()
	return unloadTrafficDropObjects(d.objs)
}

func (d *TrafficDrop) StartPacketLogging(logger *slog.Logger) error {
	d.packetLogMu.Lock()
	defer d.packetLogMu.Unlock()

	if d.packetLogReader != nil {
		return nil
	}

	reader, err := ringbuf.NewReader(d.objs.PacketLogs)
	if err != nil {
		return fmt.Errorf("create traffic drop packet log reader: %w", err)
	}

	d.packetLogReader = reader
	d.packetLogDone = make(chan struct{})

	go d.logPacketDecisions(logger, reader, d.packetLogDone)
	return nil
}

func (d *TrafficDrop) stopPacketLogging() {
	d.packetLogMu.Lock()
	reader := d.packetLogReader
	done := d.packetLogDone
	d.packetLogReader = nil
	d.packetLogDone = nil
	d.packetLogMu.Unlock()

	if reader == nil {
		return
	}

	_ = reader.Close()
	if done != nil {
		<-done
	}
}

func (d *TrafficDrop) logPacketDecisions(logger *slog.Logger, reader *ringbuf.Reader, done chan struct{}) {
	defer close(done)

	for {
		record, err := reader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) {
				return
			}
			logger.Error("failed to read traffic drop packet log", "error", err)
			continue
		}

		if len(record.RawSample) < packetLogSize {
			logger.Warn("received short traffic drop packet log", "size", len(record.RawSample))
			continue
		}

		decision := record.RawSample[10]
		ethType := binary.LittleEndian.Uint16(record.RawSample[8:10])
		ifindex := binary.LittleEndian.Uint32(record.RawSample[12:16])
		logger.Debug(
			"packet "+packetDecisionString(decision),
			"namespace", d.namespace(ifindex),
			"source", net.IP(record.RawSample[0:4]).String(),
			"destination", net.IP(record.RawSample[4:8]).String(),
			"packet_type", packetTypeString(ethType),
			"eth_type", fmt.Sprintf("0x%04x", ethType),
		)
	}
}

func (d *TrafficDrop) namespace(ifindex uint32) string {
	d.namespacesMu.RLock()
	defer d.namespacesMu.RUnlock()

	if namespace, ok := d.namespaces[ifindex]; ok {
		return namespace
	}

	return ""
}

func (d *TrafficDrop) setNamespace(ifindex uint32, namespace string) {
	d.namespacesMu.Lock()
	defer d.namespacesMu.Unlock()
	d.namespaces[ifindex] = namespace
}

func (d *TrafficDrop) deleteNamespace(ifindex uint32) {
	d.namespacesMu.Lock()
	defer d.namespacesMu.Unlock()
	delete(d.namespaces, ifindex)
}

func packetTypeString(ethType uint16) string {
	switch ethType {
	case 0x0800:
		return "ipv4"
	case 0x0806:
		return "arp"
	case 0x86dd:
		return "ipv6"
	default:
		return fmt.Sprintf("unknown(0x%04x)", ethType)
	}
}

func packetDecisionString(decision uint8) string {
	switch decision {
	case packetDecisionPass:
		return "pass"
	case packetDecisionDrop:
		return "drop"
	default:
		return fmt.Sprintf("unknown(%d)", decision)
	}
}

func unloadTrafficDropObjects(objs trafficDropObjects) error {
	var errs []error
	if objs.Program != nil {
		errs = append(errs, objs.Program.Close())
	}
	if objs.AllowedSources != nil {
		errs = append(errs, objs.AllowedSources.Close())
	}
	if objs.PacketLogs != nil {
		errs = append(errs, objs.PacketLogs.Close())
	}
	return errors.Join(errs...)
}

func (d *TrafficDrop) Attach(iface *net.Interface, namespace string) (*TrafficDropHandle, error) {
	ifindex := uint32(iface.Index)
	d.setNamespace(ifindex, namespace)
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   d.objs.Program,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode,
	})
	if err != nil {
		d.deleteNamespace(ifindex)
		return nil, fmt.Errorf("attach xdp to %s (ifindex=%d): %w", iface.Name, iface.Index, err)
	}

	return &TrafficDropHandle{
		link:        l,
		trafficDrop: d,
		ifindex:     ifindex,
	}, nil
}

func (h *TrafficDropHandle) Close() error {
	if h.trafficDrop != nil {
		h.trafficDrop.deleteNamespace(h.ifindex)
	}
	return h.link.Close()
}
