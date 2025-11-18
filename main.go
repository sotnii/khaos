package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/sotnii/khaos/packetdrop"
)

func main() {
	if len(os.Args) < 3 {
		log.Fatalf("usage: %s <iface> <port> <drop_pct>", os.Args[0])
	}

	ifname := os.Args[1]
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		log.Fatalf("Cannot determine interface by name: %s", os.Args[1])
	}

	targetPort, err := strconv.Atoi(os.Args[2])
	if err != nil {
		log.Fatalf("Invalid port: %s", os.Args[2])
	}

	if targetPort < 0 || targetPort > 65535 {
		log.Fatalf("Invalid port: %d", targetPort)
	}

	dropPct, err := strconv.Atoi(os.Args[3])
	if err != nil {
		log.Fatalf("Invalid drop_pct: %s", os.Args[3])
	}

	if dropPct < 1 || dropPct > 100 {
		log.Fatalf("Invalid drop_pct: %d", dropPct)
	}

	pd := packetdrop.NewPacketDropper(iface, targetPort, dropPct)

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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	eventTrace, err := pd.TraceEvents(ctx)
	if err != nil {
		log.Fatalf("Tracing events: %s", err)
	}

	log.Printf("Dropping %d%% of incoming packets for port %d on %v", dropPct, targetPort, ifname)

	droppedCnt := 0
	passedCnt := 0
	for event := range eventTrace {
		fmt.Println(event)
		switch event.Type {
		case packetdrop.TypePass:
			passedCnt++
		case packetdrop.TypeDrop:
			droppedCnt++
		default:
		}
	}

	fmt.Printf("\nTraced %d events, dropped %d, passed %d\n", droppedCnt+passedCnt, droppedCnt, passedCnt)
}
