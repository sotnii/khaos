package network

import (
	"encoding/binary"
	"fmt"
	"net"
)

type Allocator struct {
	network *net.IPNet
	next    uint32
	limit   uint32
}

func NewAllocator(cidr string) (*Allocator, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("parse cidr %q: %w", cidr, err)
	}

	base := binary.BigEndian.Uint32(ip.To4())
	ones, bits := network.Mask.Size()
	size := uint32(1) << uint32(bits-ones)
	if size < 4 {
		return nil, fmt.Errorf("cidr %q is too small", cidr)
	}

	return &Allocator{
		network: network,
		next:    base + 2,
		limit:   base + size - 2,
	}, nil
}

func (a *Allocator) Allocate() (net.IP, error) {
	if a.next > a.limit {
		return nil, fmt.Errorf("ip range exhausted for %s", a.network.String())
	}
	value := a.next
	a.next++

	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, value)
	return ip, nil
}

func (a *Allocator) Prefix() int {
	ones, _ := a.network.Mask.Size()
	return ones
}
