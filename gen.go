package main

//go:generate go tool bpf2go -target bpf -go-package=xdp -output-dir=xdp packetDrop bpf/packet_drop.c
