package provision

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/sotnii/pakostii/containers"
	"github.com/sotnii/pakostii/logging"
	"github.com/sotnii/pakostii/runtime/state"
	"github.com/sotnii/pakostii/runtime/util"
	"github.com/sotnii/pakostii/spec"
)

type ContainerProvisioner struct {
	manager containers.Manager
	logger  logging.Logger
}

func NewContainerProvisioner(manager containers.Manager, logger logging.Logger) *ContainerProvisioner {
	return &ContainerProvisioner{
		manager: manager,
		logger:  logger.With("component", "container_provisioner"),
	}
}

func (p *ContainerProvisioner) Provision(ctx context.Context, cs *state.ClusterState) error {
	hostsFile, err := p.buildHostsFile(cs)
	if err != nil {
		return err
	}
	p.logger.Debug("hosts file generated", "content", hostsFile)

	var (
		wg      sync.WaitGroup
		errMu   sync.Mutex
		runErrs []error
	)

	for _, node := range cs.Nodes() {
		nodeSpec := node.Spec()
		for _, containerSpec := range nodeSpec.Containers {
			wg.Add(1)
			go func(node *state.NodeState, nodeSpec spec.NodeSpec, containerSpec spec.ContainerSpec) {
				defer wg.Done()

				ns := node.Namespace()
				if ns == nil || ns.AllocatedIP == nil {
					err := fmt.Errorf("node %s network namespace not ready", nodeSpec.ID)
					p.logger.Error("container launch failed", "node", nodeSpec.ID, "service", containerSpec.Name, "error", err)
					errMu.Lock()
					runErrs = append(runErrs, err)
					errMu.Unlock()
					return
				}
				request := containers.LaunchRequest{
					ID:          fmt.Sprintf("pkst-%s-%s-%s-%s", cs.TestID(), nodeSpec.ID, containerSpec.Name, state.NewResourceID()),
					Name:        containerSpec.Name,
					NodeID:      string(nodeSpec.ID),
					ImageRef:    containerSpec.ImageRef,
					NetNSPath:   ns.Path,
					Hostname:    string(nodeSpec.ID),
					Env:         util.CopyMap(containerSpec.Env),
					Files:       util.MergeMaps(containerSpec.Files, map[string]string{"/etc/hosts": hostsFile}),
					StartDelay:  containerSpec.StartDelay,
					Readiness:   containerSpec.ReadinessProbe,
					NamespaceIP: ns.AllocatedIP.String(),
				}
				p.logger.Debug("launching container", "node", nodeSpec.ID, "service", containerSpec.Name, "container_id", request.ID, "image", request.ImageRef, "netns", request.NetNSPath, "start_delay", request.StartDelay)

				running, err := p.manager.RunContainer(ctx, request)
				if err != nil {
					p.logger.Error("container launch failed", "node", nodeSpec.ID, "service", containerSpec.Name, "container_id", request.ID, "error", err)
					errMu.Lock()
					runErrs = append(runErrs, err)
					errMu.Unlock()
					return
				}

				node.AddRunningContainer(running.ID, *running)
				p.logger.Info("container running", "node", nodeSpec.ID, "container_id", running.ID, "name", running.Name)
			}(node, nodeSpec, containerSpec)
		}
	}

	wg.Wait()
	return errors.Join(runErrs...)
}

func (p *ContainerProvisioner) buildHostsFile(state *state.ClusterState) (string, error) {
	lines := []string{
		"127.0.0.1 localhost",
		"::1 localhost ip6-localhost ip6-loopback",
	}
	for _, node := range state.Nodes() {
		nodeSpec := node.Spec()
		ns := node.Namespace()
		if ns == nil || ns.AllocatedIP == nil {
			return "", fmt.Errorf("node %s network namespace not ready", nodeSpec.ID)
		}
		p.logger.Debug("adding hosts entry", "node", nodeSpec.ID, "ip", ns.AllocatedIP.String())
		lines = append(lines, fmt.Sprintf("%s %s", ns.AllocatedIP.String(), nodeSpec.ID))
	}
	return util.JoinLines(lines), nil
}
