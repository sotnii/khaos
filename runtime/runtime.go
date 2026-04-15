package runtime

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sotnii/pakostii/containers"
	"github.com/sotnii/pakostii/logging"
	"github.com/sotnii/pakostii/network"
	"github.com/sotnii/pakostii/runtime/provision"
	"github.com/sotnii/pakostii/runtime/state"
	"github.com/sotnii/pakostii/runtime/util"
	"github.com/sotnii/pakostii/spec"
)

type Runtime struct {
	name                 string
	cluster              *spec.ClusterSpec
	logger               logging.Logger
	state                *state.ClusterState
	network              *network.Manager
	containers           containers.Manager
	networkProvisioner   *provision.NetworkProvisioner
	containerProvisioner *provision.ContainerProvisioner
	workDir              string
	artifactsDir         string
}

func NewRuntime(name string, cluster *spec.ClusterSpec, logger logging.Logger) (*Runtime, error) {
	workDir := filepath.Join(os.TempDir(), "pakostii")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	netManager, err := network.NewManager("pkst", network.ExecCommander{}, logger.With("component", "network"))
	if err != nil {
		return nil, err
	}

	containerManager, err := containers.NewManager(containers.Config{
		Socket:      containers.DefaultSocket,
		Namespace:   containers.DefaultNamespace,
		Snapshotter: containers.DefaultSnapshotter,
		WorkDir:     workDir,
		Logger:      logger.With("component", "containerd"),
	})
	if err != nil {
		return nil, err
	}

	cs := state.NewClusterState(cluster)

	return &Runtime{
		name:                 name,
		cluster:              cluster,
		logger:               logger.With("test", name),
		state:                cs,
		network:              netManager,
		containers:           containerManager,
		networkProvisioner:   provision.NewNetworkProvisioner(netManager, logger.With("test", name)),
		containerProvisioner: provision.NewContainerProvisioner(containerManager, logger.With("test", name)),
		workDir:              workDir,
		artifactsDir:         filepath.Join(".pakostii", fmt.Sprintf("%s-%s", name, cs.TestID())),
	}, nil
}

func (r *Runtime) Run(ctx context.Context, fn func(*Context) error) (runErr error) {
	ctx, cancel := context.WithCancel(ctx)
	r.logger.Info("runtime starting", "nodes", len(r.cluster.Nodes), "artifacts_dir", r.artifactsDir, "work_dir", r.workDir)
	defer cancel()
	defer func() {
		teardownCtx, teardownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer teardownCancel()

		teardownErr := r.teardown(teardownCtx)
		if runErr == nil {
			runErr = teardownErr
		} else if teardownErr != nil {
			runErr = errors.Join(runErr, teardownErr)
		}
		_ = r.containers.Close()
		r.logger.Info("runtime finished", "error", runErr)
	}()

	if err := r.prepare(ctx); err != nil {
		return err
	}

	handle := &Handle{
		ctx:     ctx,
		state:   r.state,
		manager: r.containers,
		logger:  r.logger,
	}

	return r.runTest(ctx, cancel, newContext(handle), fn)
}

func (r *Runtime) prepare(ctx context.Context) error {
	r.logger.Info("preparing runtime", "test_id", r.state.TestID())
	if err := r.networkProvisioner.Provision(ctx, r.state); err != nil {
		return err
	}
	if err := r.containerProvisioner.Provision(ctx, r.state); err != nil {
		return err
	}
	return nil
}

func (r *Runtime) runTest(ctx context.Context, cancel context.CancelFunc, handle *Context, fn func(*Context) error) error {
	events, errs, err := r.containers.ObserveEvents(ctx)
	if err != nil {
		r.logger.Warn("container event subscription failed", "error", err)
	}

	testErr := make(chan error, 1)
	go func() {
		r.logger.Info("starting test")
		testErr <- fn(handle)
	}()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)

	var testFinished bool

	for {
		select {
		case err := <-testErr:
			testFinished = true
			r.logger.Info("user test callback finished", "error", err)
			cancel()
			return err
		case sig := <-signals:
			r.logger.Warn("received termination signal", "signal", sig.String())
			cancel()
			return fmt.Errorf("%w: %s", ErrTestCancelled, sig.String())
		case event, ok := <-events:
			if ok {
				r.logger.Warn("container process exited", "container_id", event.ContainerID, "exec_id", event.ExecID, "exit_code", event.ExitCode)
			} else {
				events = nil
			}
		case err, ok := <-errs:
			if ok && err != nil {
				r.logger.Warn("container event stream failed", "error", err)
			} else {
				errs = nil
			}
		case <-ctx.Done():
			if testFinished || errors.Is(ctx.Err(), context.Canceled) {
				r.logger.Debug("runtime context canceled after normal completion")
				return nil
			}
			return ctx.Err()
		}
	}
}

func (r *Runtime) teardown(ctx context.Context) error {
	r.logger.Info("tearing down runtime")
	var errs []error

	for _, node := range r.state.DrainNodes() {
		nodeSpec := node.Spec()
		nodeNS := node.Namespace()
		r.logger.Debug("tearing down node", "node", nodeSpec.ID)
		for _, container := range node.Containers() {
			if err := r.collectContainerArtifacts(nodeSpec.ID, container); err != nil {
				r.logger.Error("artifact collection failed", "node", nodeSpec.ID, "service", container.Name, "error", err)
				errs = append(errs, err)
			}
			if err := r.containers.TeardownContainer(ctx, container); err != nil {
				r.logger.Error("container teardown failed", "node", nodeSpec.ID, "container_id", container.ID, "error", err)
				errs = append(errs, err)
			}
		}
		if err := r.network.TeardownNamespace(ctx, nodeNS); err != nil {
			namespaceName := "<nil>"
			if nodeNS != nil {
				namespaceName = nodeNS.Name
			}
			r.logger.Error("namespace teardown failed", "node", nodeSpec.ID, "namespace", namespaceName, "error", err)
			errs = append(errs, err)
		}
	}

	if err := r.network.TeardownNamespace(ctx, r.state.AgentNamespace()); err != nil {
		r.logger.Error("agent namespace teardown failed", "error", err)
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (r *Runtime) collectContainerArtifacts(nodeID spec.NodeID, ctr containers.RunningContainer) error {
	dstDir := filepath.Join(r.artifactsDir, "logs", string(nodeID), ctr.Name)
	r.logger.Debug("collecting container artifacts", "node", nodeID, "service", ctr.Name, "src", ctr.IO.Dir, "dst", dstDir)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create artifact dir for %s/%s: %w", nodeID, ctr.Name, err)
	}

	if err := util.CopyFile(ctr.IO.Stdout, filepath.Join(dstDir, "stdout")); err != nil {
		return fmt.Errorf("copy stdout for %s/%s: %w", nodeID, ctr.Name, err)
	}
	if err := util.CopyFile(ctr.IO.Stderr, filepath.Join(dstDir, "stderr")); err != nil {
		return fmt.Errorf("copy stderr for %s/%s: %w", nodeID, ctr.Name, err)
	}

	r.logger.Info("container artifacts collected", "node", nodeID, "service", ctr.Name, "dst", dstDir)
	return nil
}
