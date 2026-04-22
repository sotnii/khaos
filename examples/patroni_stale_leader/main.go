package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/lmittmann/tint"
	"github.com/sotnii/pakostii"
	"github.com/sotnii/pakostii/spec"
)

//go:embed patroni.yml
var patroniConfig string

type PatroniLeaderResp struct {
	Role string `json:"role"`
}

func main() {
	logger := slog.New(tint.NewHandler(os.Stdout, &tint.Options{
		Level: slog.LevelDebug,
	}))

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

	test := pakostii.NewTest(
		"patroni_stale_leader",
		cluster,
		pakostii.WithLogger(logger),
	)

	err := test.Run(context.Background(), func(t *pakostii.TestHandle) error {
		resp, err := t.Http().Get("http://db1:8008/leader", time.Second*5)
		if err != nil {
			return err
		}
		var p PatroniLeaderResp
		err = json.Unmarshal(resp.Body, &p)
		if err != nil {
			return err
		}
		if p.Role != "primary" {
			return fmt.Errorf("expected db1 to be cluster leader after cluster startup, instead got %v", p.Role)
		}
		return nil
	})

	if err != nil {
		logger.Error("test run failed", "err", err)
	}
}
