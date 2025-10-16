package main

import (
	"context"
	"fmt"
	"github.com/sotnii/khaos/xdp"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	if len(os.Args) < 2 {
		log.Fatalf("usage: %s <ifname>", os.Args[0])
	}

	ifname := os.Args[1]
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Getting interface %s: %s", ifname, err)
	}
	pd := xdp.NewPacketDropper(iface)

	err = pd.Attach()
	if err != nil {
		panic(err)
	}
	defer func() {
		err := pd.Close()
		if err != nil {
			log.Fatalf("Closing packet dropper: %s", err)
		}
	}()

	log.Printf("Dropping packets on %s", ifname)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eventTrace, err := pd.TraceEvents(ctx)
	if err != nil {
		log.Fatalf("Tracing events: %s", err)
	}

	for event := range eventTrace {
		fmt.Println(event)
	}
}
