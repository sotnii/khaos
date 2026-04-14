package main

import (
	"context"
	_ "embed"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/sotnii/pakostii/runtime"
	"github.com/sotnii/pakostii/spec"
)

//go:embed patroni.yml
var patroniConfig string

func main() {
	logger := runtime.NewLogger(os.Stdout, slog.LevelDebug)

	cluster := spec.NewCluster("patroni_stale_leader")
	etcdHosts := []spec.NodeID{"etcd1", "etcd2", "etcd3"}

	for i := 0; i < 3; i++ {
		az := fmt.Sprintf("az%d", i+1)
		etcd := spec.Etcd(
			"etcd",
			"quay.io/coreos/etcd:v3.5.29",
			spec.EtcdConfig{
				Name:         fmt.Sprintf("etcd%d", i+1),
				RunsOnHost:   etcdHosts[i],
				ClusterHosts: etcdHosts,
			},
		)
		cluster.AddNode(spec.NewNode(string(etcdHosts[i])).WithAZ(az).Runs(etcd))
	}

	for i := 0; i < 3; i++ {
		az := fmt.Sprintf("az%d", i+1)
		nodeID := fmt.Sprintf("db%d", i+1)
		delay := 5 * time.Second
		if i == 0 {
			delay = 0
		}

		patroni := spec.Patroni(
			"patroni",
			"ghcr.io/sotnii/patroni:4.0.5-pg17",
			spec.PatroniConfig{
				Name:        fmt.Sprintf("patroni_stale_leader_%d", i+1),
				NodeAddress: spec.NodeID(nodeID),
				EtcdHosts:   etcdHosts,
			},
			patroniConfig,
		).WithStartDelay(delay)

		cluster.AddNode(spec.NewNode(nodeID).WithAZ(az).Runs(patroni))
	}

	test := runtime.NewTest(
		"patroni_stale_leader",
		cluster,
		runtime.WithLogger(logger),
	)

	err := test.Run(context.Background(), func(ctx *runtime.Context) error {
		time.Sleep(5 * time.Second)

		first, err := ctx.Exec().InContainer("db1", "patroni", "curl", "http://0.0.0.0:8008/leader")
		if err != nil {
			fmt.Printf("exec error: %v\n", err)
		} else {
			fmt.Printf("db1 leader: %+v\n", first)
		}

		second, err := ctx.Exec().InContainer("db2", "patroni", "curl", "http://0.0.0.0:8008/leader")
		if err != nil {
			fmt.Printf("exec error: %v\n", err)
		} else {
			fmt.Printf("db2 leader: %+v\n", second)
		}

		time.Sleep(100 * time.Second)
		return nil
	})

	if err != nil {
		logger.Error("test run failed: %v", err)
	}
}
