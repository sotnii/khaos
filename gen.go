package main

//go:generate go tool bpf2go -target bpf -go-package=packetdrop -output-dir=packetdrop packetDrop bpf/packet_drop.c
