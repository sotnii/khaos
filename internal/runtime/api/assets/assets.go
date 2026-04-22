package assets

import _ "embed"

//go:embed xdp-packet-drop.bpf.o
var xdpPacketDropObject []byte
