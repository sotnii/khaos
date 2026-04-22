package pakostii

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/sotnii/pakostii/internal/containers"
	"github.com/sotnii/pakostii/internal/network"
	"github.com/sotnii/pakostii/internal/runtime"
	"github.com/sotnii/pakostii/internal/runtime/agent"
	"github.com/sotnii/pakostii/internal/runtime/managers"
	"github.com/sotnii/pakostii/internal/runtime/util"
	"github.com/sotnii/pakostii/spec"
)

type TestRuntime struct {
	id           string
	name         string
	spec         spec.ClusterSpec
	logger       *slog.Logger
	network      managers.NetworkManager
	containers   managers.ContainerManager
	workDir      string
	artifactsDir string
}

func NewTestRuntime(name string, cluster spec.ClusterSpec, logger *slog.Logger) (*TestRuntime, error) {
	workDir := filepath.Join(os.TempDir(), "pakostii")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		return nil, fmt.Errorf("create work dir: %w", err)
	}

	nsMgr, err := network.NewManager("pkst", network.ExecCommander{}, logger.With("component", "network"))
	if err != nil {
		return nil, err
	}

	containerRuntimeManager, err := containers.NewRuntimeManager(containers.Config{
		Socket:      containers.DefaultSocket,
		Namespace:   containers.DefaultNamespace,
		Snapshotter: containers.DefaultSnapshotter,
		WorkDir:     workDir,
		Logger:      logger.With("component", "containerd"),
	})
	if err != nil {
		return nil, err
	}

	testId := util.NewResourceID()
	return &TestRuntime{
		id:           testId,
		name:         name,
		spec:         cluster,
		logger:       logger,
		containers:   managers.NewContainerManager(containerRuntimeManager, logger),
		network:      managers.NewNetworkManager(nsMgr, logger),
		workDir:      workDir,
		artifactsDir: filepath.Join(".pakostii", fmt.Sprintf("%s-%s", name, testId)),
	}, nil
}

func (r *TestRuntime) Run(ctx context.Context, fn func(*TestHandle) error) (runErr error) {
	ctx, cancel := context.WithCancel(ctx)
	r.logger.Info("test runtime starting", "nodes", len(r.spec.Nodes), "artifacts_dir", r.artifactsDir, "work_dir", r.workDir)
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
		r.logger.Debug("test runtime finished", "error", runErr)
	}()

	if err := r.prepare(ctx); err != nil {
		return err
	}

	agentNs := r.network.AgentNamespace()
	if agentNs == nil {
		return errors.New("agent namespace not initialized, could not proceed the test")
	}
	httpAgent, err := agent.NewClusterHttpAgent(agentNs.Path, r.network.NodeIPs())
	if err != nil {
		return err
	}
	defer httpAgent.Close()

	handle := &clusterHandle{
		ctx:        ctx,
		containers: &r.containers,
		logger:     r.logger,
		httpAgent:  httpAgent,
	}

	return r.runTest(ctx, cancel, newTestHandle(handle), fn)
}

func (r *TestRuntime) prepare(ctx context.Context) error {
	r.logger.Info("preparing runtime", "test_id", r.id)
	if err := r.network.Prepare(ctx, r.spec); err != nil {
		return err
	}
	if err := r.containers.Prepare(ctx, r.spec, r.id, &r.network); err != nil {
		return err
	}
	return nil
}

func (r *TestRuntime) runTest(ctx context.Context, cancel context.CancelFunc, handle *TestHandle, fn func(*TestHandle) error) error {
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
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM, syscall.SIGINT)
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
			return fmt.Errorf("%w: %s", runtime.ErrTestCancelled, sig.String())
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

func (r *TestRuntime) teardown(ctx context.Context) error {
	r.logger.Info("tearing down runtime")
	var errs []error

	for _, node := range r.spec.Nodes {
		for _, container := range r.containers.ContainersOf(node.ID) {
			if err := r.collectContainerArtifacts(node.ID, container); err != nil {
				r.logger.Error("artifact collection failed", "node", node.ID, "service", container.Name, "error", err)
				errs = append(errs, err)
			}
		}
	}

	err := r.containers.Teardown(ctx)
	if err != nil {
		errs = append(errs, err)
	}

	err = r.network.Teardown(ctx)
	if err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (r *TestRuntime) collectContainerArtifacts(nodeID spec.NodeID, ctr containers.RunningContainer) error {
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
