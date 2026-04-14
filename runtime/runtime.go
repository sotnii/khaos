package runtime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/sotnii/pakostii/containers"
	"github.com/sotnii/pakostii/network"
	"github.com/sotnii/pakostii/spec"
)

type Runtime struct {
	name         string
	cluster      *spec.ClusterSpec
	logger       Logger
	state        *clusterState
	network      *network.Manager
	containers   containers.Manager
	workDir      string
	artifactsDir string
}

func NewRuntime(name string, cluster *spec.ClusterSpec, logger Logger) (*Runtime, error) {
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

	state := newClusterState(cluster)

	return &Runtime{
		name:         name,
		cluster:      cluster,
		logger:       logger.With("test", name),
		state:        state,
		network:      netManager,
		containers:   containerManager,
		workDir:      workDir,
		artifactsDir: filepath.Join(".pakostii", fmt.Sprintf("%s-%s", name, state.TestID())),
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
	if err := r.provisionNetwork(ctx); err != nil {
		return err
	}
	if err := r.provisionContainers(ctx); err != nil {
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

	for _, node := range r.state.drainNodes() {
		r.logger.Debug("tearing down node", "node", node.spec.ID)
		for _, containerState := range node.containers {
			if containerState.running != nil {
				if err := r.collectContainerArtifacts(node.spec.ID, containerState.running); err != nil {
					r.logger.Error("artifact collection failed", "node", node.spec.ID, "service", containerState.running.Name, "error", err)
					errs = append(errs, err)
				}
				if err := r.containers.TeardownContainer(ctx, containerState.running); err != nil {
					r.logger.Error("container teardown failed", "node", node.spec.ID, "container_id", containerState.running.ID, "error", err)
					errs = append(errs, err)
				}
			}
		}
		if err := r.network.TeardownNamespace(ctx, node.namespace); err != nil {
			r.logger.Error("namespace teardown failed", "node", node.spec.ID, "namespace", node.namespace.Name, "error", err)
			errs = append(errs, err)
		}
	}

	if err := r.network.TeardownNamespace(ctx, r.state.AgentNamespace()); err != nil {
		r.logger.Error("agent namespace teardown failed", "error", err)
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (r *Runtime) collectContainerArtifacts(nodeID spec.NodeID, ctr *containers.RunningContainer) error {
	dstDir := filepath.Join(r.artifactsDir, "logs", string(nodeID), ctr.Name)
	r.logger.Debug("collecting container artifacts", "node", nodeID, "service", ctr.Name, "src", ctr.IO.Dir, "dst", dstDir)
	if err := os.MkdirAll(dstDir, 0o755); err != nil {
		return fmt.Errorf("create artifact dir for %s/%s: %w", nodeID, ctr.Name, err)
	}

	if err := copyFile(ctr.IO.Stdin, filepath.Join(dstDir, "stdin")); err != nil {
		return fmt.Errorf("copy stdin for %s/%s: %w", nodeID, ctr.Name, err)
	}
	if err := copyFile(ctr.IO.Stdout, filepath.Join(dstDir, "stdout")); err != nil {
		return fmt.Errorf("copy stdout for %s/%s: %w", nodeID, ctr.Name, err)
	}
	if err := copyFile(ctr.IO.Stderr, filepath.Join(dstDir, "stderr")); err != nil {
		return fmt.Errorf("copy stderr for %s/%s: %w", nodeID, ctr.Name, err)
	}

	r.logger.Info("container artifacts collected", "node", nodeID, "service", ctr.Name, "dst", dstDir)
	return nil
}

func (r *Runtime) provisionNetwork(ctx context.Context) error {
	r.logger.Info("provisioning network")
	if err := r.network.SetupBridge(ctx); err != nil {
		return err
	}

	agentNS, err := r.network.CreateNamespace(ctx, newResourceID(), "agent")
	if err != nil {
		return err
	}
	if err := r.network.SetupNamespace(ctx, agentNS); err != nil {
		return err
	}
	r.logger.Debug("agent namespace ready", "namespace", agentNS.Name, "path", agentNS.Path)

	r.state.WithWrite(func() {
		r.state.agentNamespace = agentNS
	})

	for _, node := range r.state.Nodes() {
		r.logger.Debug("provisioning node namespace", "node", node.spec.ID, "resource_id", node.resourceID)
		ns, err := r.network.CreateNamespace(ctx, node.resourceID, fmt.Sprintf("node-%s", node.resourceID))
		if err != nil {
			return err
		}
		if err := r.network.SetupNamespace(ctx, ns); err != nil {
			return err
		}

		current := node
		r.state.WithWrite(func() {
			current.namespace = ns
		})
	}

	return nil
}

func (r *Runtime) provisionContainers(ctx context.Context) error {
	hostsFile, err := r.buildHostsFile()
	if err != nil {
		return err
	}
	r.logger.Debug("hosts file generated", "content", hostsFile)

	var (
		wg      sync.WaitGroup
		errMu   sync.Mutex
		runErrs []error
	)

	for _, node := range r.state.Nodes() {
		for _, containerSpec := range node.spec.Containers {
			node := node
			containerSpec := containerSpec
			wg.Add(1)
			go func() {
				defer wg.Done()

				request := containers.LaunchRequest{
					ID:          fmt.Sprintf("pkst-%s-%s-%s-%s", r.state.TestID(), node.spec.ID, containerSpec.Name, newResourceID()),
					Name:        containerSpec.Name,
					NodeID:      string(node.spec.ID),
					ImageRef:    containerSpec.ImageRef,
					NetNSPath:   node.namespace.Path,
					Hostname:    string(node.spec.ID),
					Env:         copyMap(containerSpec.Env),
					Files:       mergeMaps(containerSpec.Files, map[string]string{"/etc/hosts": hostsFile}),
					StartDelay:  containerSpec.StartDelay,
					Readiness:   containerSpec.ReadinessProbe,
					NamespaceIP: node.namespace.AllocatedIP.String(),
				}
				r.logger.Debug("launching container", "node", node.spec.ID, "service", containerSpec.Name, "container_id", request.ID, "image", request.ImageRef, "netns", request.NetNSPath, "start_delay", request.StartDelay)

				running, err := r.containers.RunContainer(ctx, request)
				if err != nil {
					r.logger.Error("container launch failed", "node", node.spec.ID, "service", containerSpec.Name, "container_id", request.ID, "error", err)
					errMu.Lock()
					runErrs = append(runErrs, err)
					errMu.Unlock()
					return
				}

				r.state.WithWrite(func() {
					node.containers[running.ID] = &containerState{running: running}
				})
				r.logger.Info("container running", "node", node.spec.ID, "container_id", running.ID, "name", running.Name)
			}()
		}
	}

	wg.Wait()
	return errors.Join(runErrs...)
}

func (r *Runtime) buildHostsFile() (string, error) {
	lines := []string{
		"127.0.0.1 localhost",
		"::1 localhost ip6-localhost ip6-loopback",
	}
	for _, node := range r.state.Nodes() {
		if node.namespace == nil || node.namespace.AllocatedIP == nil {
			return "", fmt.Errorf("node %s network namespace not ready", node.spec.ID)
		}
		r.logger.Debug("adding hosts entry", "node", node.spec.ID, "ip", node.namespace.AllocatedIP.String())
		lines = append(lines, fmt.Sprintf("%s %s", node.namespace.AllocatedIP.String(), node.spec.ID))
	}
	return joinLines(lines), nil
}

func copyMap(src map[string]string) map[string]string {
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

func mergeMaps(a, b map[string]string) map[string]string {
	out := copyMap(a)
	for k, v := range b {
		out[k] = v
	}
	return out
}

func joinLines(lines []string) string {
	result := ""
	for i, line := range lines {
		if i > 0 {
			result += "\n"
		}
		result += line
	}
	return result
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
