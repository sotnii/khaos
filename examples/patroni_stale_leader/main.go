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

type PatroniNodeState struct {
	Role    string `json:"role"`
	Patroni struct {
		Name string `json:"name"`
	} `json:"patroni"`
}

type PatroniCluster struct {
	Members []struct {
		Name string `json:"name"`
		Role string `json:"role"`
	} `json:"members"`
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

	test.Run(context.Background(), func(t *pakostii.TestHandle) error {
		time.Sleep(10 * time.Second) // A hack until readiness probes are missing

		p, err := getPatroniNodeState(t, "db1")
		if p.Role != "primary" {
			return fmt.Errorf("expected db1 to be cluster leader after cluster startup, instead got %v", p.Role)
		}

		i, err := t.Network().Partition().IsolateAZ("az1")
		if err != nil {
			return err
		}
		err = i.Apply()
		if err != nil {
			return err
		}

		newLeader, err := waitForLeaderChange(t, p.Patroni.Name, time.Second*60, logger)
		if err != nil {
			return err
		}
		logger.Info("leader changed", "newLeader", newLeader)

		err = i.Heal()
		if err != nil {
			return err
		}

		time.Sleep(time.Second * 30)
		p, err = getPatroniNodeState(t, "db1")
		if err != nil {
			return err
		}
		logger.Info("db1 after heal state", "state", p)

		// TODO: Check that after healing, db1 does not thing that it's a leader

		return nil
	})
}

func getPatroniNodeState(t *pakostii.TestHandle, node string) (*PatroniNodeState, error) {
	resp, err := t.Http().Get(fmt.Sprintf("http://%s:8008/leader", node), time.Second*5)
	if err != nil {
		return nil, err
	}
	var p PatroniNodeState
	err = json.Unmarshal(resp.Body, &p)
	if err != nil {
		return nil, err
	}
	return &p, nil
}

func waitForLeaderChange(t *pakostii.TestHandle, originalClusterLeader string, timeout time.Duration, logger *slog.Logger) (string, error) {
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	timeoutTimer := time.NewTimer(timeout)
	defer timeoutTimer.Stop()
	for {
		select {
		case <-tick.C:
			cluster, err := fetchClusterState(t, "db2", time.Second*5)
			if err != nil {
				logger.Error("failed to fetch cluster state", "err", err)
				continue
			}

			logger.Debug("fetched cluster state", "state", cluster)
			for _, member := range cluster.Members {
				if member.Role == "leader" && member.Name != originalClusterLeader {
					return member.Name, nil
				}
			}
		case <-t.Ctx.Done():
			return "", fmt.Errorf("text context cancelled")
		case <-timeoutTimer.C:
			return "", fmt.Errorf("timed out waiting for leader change")
		}
	}
}

func fetchClusterState(t *pakostii.TestHandle, node string, timeout time.Duration) (*PatroniCluster, error) {
	resp, err := t.Http().Get(fmt.Sprintf("http://%s:8008/cluster", node), timeout)
	if err != nil {
		return nil, err
	}
	var cluster PatroniCluster
	err = json.Unmarshal(resp.Body, &cluster)
	if err != nil {
		return nil, err
	}
	return &cluster, nil
}
