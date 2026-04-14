package containers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/containerd/containerd"
	containerevents "github.com/containerd/containerd/api/events"
	"github.com/containerd/containerd/cio"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/containerd/oci"
	"github.com/containerd/errdefs"
	typeurl "github.com/containerd/typeurl/v2"
	specs "github.com/opencontainers/runtime-spec/specs-go"
)

type Logger interface {
	Debug(msg string, args ...any)
	Info(msg string, args ...any)
	Warn(msg string, args ...any)
	Error(msg string, args ...any)
}

type Config struct {
	Socket      string
	Namespace   string
	Snapshotter string
	WorkDir     string
	Logger      Logger
}

type manager struct {
	client      *containerd.Client
	namespace   string
	snapshotter string
	workDir     string
	logger      Logger
}

func NewManager(cfg Config) (Manager, error) {
	client, err := containerd.New(
		cfg.Socket,
		containerd.WithDefaultNamespace(cfg.Namespace),
	)
	if err != nil {
		return nil, fmt.Errorf("connect to containerd: %w", err)
	}

	logger := cfg.Logger
	if logger == nil {
		logger = nopLogger{}
	}

	return &manager{
		client:      client,
		namespace:   cfg.Namespace,
		snapshotter: cfg.Snapshotter,
		workDir:     cfg.WorkDir,
		logger:      logger,
	}, nil
}

func (m *manager) RunContainer(ctx context.Context, req LaunchRequest) (*RunningContainer, error) {
	ctx = namespaces.WithNamespace(ctx, m.namespace)

	if req.StartDelay > 0 {
		timer := time.NewTimer(req.StartDelay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timer.C:
		}
	}

	image, err := m.client.Pull(ctx, req.ImageRef, containerd.WithPullUnpack)
	if err != nil {
		return nil, fmt.Errorf("pull image %s: %w", req.ImageRef, err)
	}

	bundleDir, mounts, err := m.prepareFiles(req.ID, req.Files)
	if err != nil {
		return nil, err
	}
	containerIO, stdoutWriter, stderrWriter, err := m.prepareContainerIO(req.ID)
	if err != nil {
		_ = os.RemoveAll(bundleDir)
		return nil, err
	}

	snapshotKey := req.ID + "-snapshot"
	opts := []containerd.NewContainerOpts{
		containerd.WithSnapshotter(m.snapshotter),
		containerd.WithNewSnapshot(snapshotKey, image),
		containerd.WithImage(image),
		containerd.WithContainerLabels(map[string]string{
			"pakostii.node": req.NodeID,
		}),
		containerd.WithNewSpec(
			oci.WithImageConfig(image),
			oci.WithEnv(envSlice(req.Env)),
			oci.WithHostname(req.Hostname),
			oci.WithLinuxNamespace(specs.LinuxNamespace{
				Type: specs.NetworkNamespace,
				Path: req.NetNSPath,
			}),
			oci.WithMounts(mounts),
		),
	}

	container, err := m.client.NewContainer(ctx, req.ID, opts...)
	if err != nil {
		_ = os.RemoveAll(containerIO.Dir)
		_ = os.RemoveAll(bundleDir)
		return nil, fmt.Errorf("create container %s: %w", req.ID, err)
	}

	task, err := container.NewTask(
		ctx,
		cio.NewCreator(
			cio.WithStreams(nil, stdoutWriter, stderrWriter),
			cio.WithFIFODir(containerIO.Dir),
		),
	)
	if err != nil {
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		_ = os.RemoveAll(containerIO.Dir)
		_ = os.RemoveAll(bundleDir)
		return nil, fmt.Errorf("create task for %s: %w", req.ID, err)
	}

	if err := task.Start(ctx); err != nil {
		_, _ = task.Delete(ctx)
		_ = container.Delete(ctx, containerd.WithSnapshotCleanup)
		_ = os.RemoveAll(containerIO.Dir)
		_ = os.RemoveAll(bundleDir)
		return nil, fmt.Errorf("start task for %s: %w", req.ID, err)
	}

	m.logger.Info("container started", "container_id", req.ID, "image", req.ImageRef)
	return &RunningContainer{
		ID:          req.ID,
		Name:        req.Name,
		NodeID:      req.NodeID,
		SnapshotKey: snapshotKey,
		BundleDir:   bundleDir,
		IO:          containerIO,
	}, nil
}

func (m *manager) TeardownContainer(ctx context.Context, ctr *RunningContainer) error {
	ctx = namespaces.WithNamespace(ctx, m.namespace)
	container, err := m.client.LoadContainer(ctx, ctr.ID)
	if err != nil {
		if errdefs.IsNotFound(err) {
			return nil
		}
		return fmt.Errorf("load container %s: %w", ctr.ID, err)
	}

	task, err := container.Task(ctx, nil)
	if err == nil {
		_ = task.Kill(ctx, syscall.SIGKILL)
		_, _ = task.Delete(ctx, containerd.WithProcessKill)
	}

	err = container.Delete(ctx, containerd.WithSnapshotCleanup)
	if removeErr := os.RemoveAll(ctr.BundleDir); removeErr != nil {
		err = errors.Join(err, removeErr)
	}
	if ctr.IO.Dir != "" {
		if removeErr := os.RemoveAll(ctr.IO.Dir); removeErr != nil {
			err = errors.Join(err, removeErr)
		}
	}
	if err != nil {
		return fmt.Errorf("delete container %s: %w", ctr.ID, err)
	}
	return nil
}

func (m *manager) prepareContainerIO(containerID string) (ContainerIO, io.Writer, io.Writer, error) {
	root := filepath.Join(m.workDir, "logs", containerID)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return ContainerIO{}, nil, nil, fmt.Errorf("create io dir for %s: %w", containerID, err)
	}

	stdinPath := filepath.Join(root, "stdin")
	stdoutPath := filepath.Join(root, "stdout")
	stderrPath := filepath.Join(root, "stderr")

	stdinFile, err := os.OpenFile(stdinPath, os.O_CREATE|os.O_TRUNC|os.O_RDWR, 0o644)
	if err != nil {
		return ContainerIO{}, nil, nil, fmt.Errorf("create stdin file for %s: %w", containerID, err)
	}
	if err := stdinFile.Close(); err != nil {
		return ContainerIO{}, nil, nil, fmt.Errorf("close stdin file for %s: %w", containerID, err)
	}

	stdoutFile, err := os.OpenFile(stdoutPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return ContainerIO{}, nil, nil, fmt.Errorf("create stdout file for %s: %w", containerID, err)
	}
	if err := stdoutFile.Close(); err != nil {
		return ContainerIO{}, nil, nil, fmt.Errorf("close stdout file for %s: %w", containerID, err)
	}
	stderrFile, err := os.OpenFile(stderrPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return ContainerIO{}, nil, nil, fmt.Errorf("create stderr file for %s: %w", containerID, err)
	}
	if err := stderrFile.Close(); err != nil {
		return ContainerIO{}, nil, nil, fmt.Errorf("close stderr file for %s: %w", containerID, err)
	}

	return ContainerIO{
		Dir:    root,
		Stdin:  stdinPath,
		Stdout: stdoutPath,
		Stderr: stderrPath,
	}, fileAppender{path: stdoutPath}, fileAppender{path: stderrPath}, nil
}

func (m *manager) ExecInContainer(ctx context.Context, containerID string, argv []string) (*ExecResult, error) {
	ctx = namespaces.WithNamespace(ctx, m.namespace)

	container, err := m.client.LoadContainer(ctx, containerID)
	if err != nil {
		return nil, fmt.Errorf("load container %s: %w", containerID, err)
	}
	task, err := container.Task(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("load task for %s: %w", containerID, err)
	}

	execID := "exec-" + filepath.Base(filepath.Clean(fmt.Sprintf("%d-%s", time.Now().UnixNano(), containerID)))
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	processSpec := &specs.Process{
		Args:     argv,
		Cwd:      "/",
		Terminal: false,
	}

	ioDir := filepath.Join(m.workDir, "exec", execID)
	if err := os.MkdirAll(ioDir, 0o755); err != nil {
		return nil, fmt.Errorf("create exec io dir: %w", err)
	}
	defer os.RemoveAll(ioDir)

	process, err := task.Exec(
		ctx,
		execID,
		processSpec,
		cio.NewCreator(
			cio.WithStreams(nil, &stdout, &stderr),
			cio.WithFIFODir(ioDir),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("create exec process in %s: %w", containerID, err)
	}

	statusC, err := process.Wait(ctx)
	if err != nil {
		return nil, fmt.Errorf("wait on exec process %s: %w", execID, err)
	}

	if err := process.Start(ctx); err != nil {
		return nil, fmt.Errorf("start exec process %s: %w", execID, err)
	}

	select {
	case <-ctx.Done():
		_ = process.Kill(context.Background(), syscall.SIGKILL)
		_, _ = process.Delete(context.Background(), containerd.WithProcessKill)
		return nil, ctx.Err()
	case status := <-statusC:
		exitCode, _, waitErr := status.Result()
		if _, err := process.Delete(ctx); err != nil && !errdefs.IsNotFound(err) {
			waitErr = errors.Join(waitErr, err)
		}
		if waitErr != nil {
			return nil, fmt.Errorf("exec process %s failed: %w", execID, waitErr)
		}
		return &ExecResult{
			ExitCode: exitCode,
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
		}, nil
	}
}

func (m *manager) ObserveEvents(ctx context.Context) (<-chan Event, <-chan error, error) {
	ctx = namespaces.WithNamespace(ctx, m.namespace)
	stream, errs := m.client.Subscribe(ctx)
	out := make(chan Event, 16)
	errOut := make(chan error, 1)

	go func() {
		defer close(out)
		defer close(errOut)
		for {
			select {
			case <-ctx.Done():
				return
			case err, ok := <-errs:
				if !ok {
					return
				}
				if err != nil {
					errOut <- err
				}
			case envelope, ok := <-stream:
				if !ok {
					return
				}
				if envelope.Topic != "/tasks/exit" || envelope.Event == nil {
					continue
				}
				payload, err := typeurl.UnmarshalAny(envelope.Event)
				if err != nil {
					errOut <- err
					continue
				}
				taskExit, ok := payload.(*containerevents.TaskExit)
				if !ok {
					continue
				}
				out <- Event{
					ContainerID: taskExit.ContainerID,
					ExecID:      taskExit.ID,
					ExitCode:    taskExit.ExitStatus,
				}
			}
		}
	}()

	return out, errOut, nil
}

func (m *manager) Close() error {
	return m.client.Close()
}

func (m *manager) prepareFiles(containerID string, files map[string]string) (string, []specs.Mount, error) {
	root := filepath.Join(m.workDir, "mounts", containerID)
	if err := os.MkdirAll(root, 0o755); err != nil {
		return "", nil, fmt.Errorf("create mount root for %s: %w", containerID, err)
	}

	mounts := make([]specs.Mount, 0, len(files))
	for target, content := range files {
		source := filepath.Join(root, sanitizeTarget(target))
		if err := os.MkdirAll(filepath.Dir(source), 0o755); err != nil {
			return "", nil, fmt.Errorf("create host dir for %s: %w", target, err)
		}
		if err := os.WriteFile(source, []byte(content), 0o644); err != nil {
			return "", nil, fmt.Errorf("write injected file %s: %w", target, err)
		}

		mounts = append(mounts, specs.Mount{
			Destination: target,
			Type:        "bind",
			Source:      source,
			Options:     []string{"rbind", "ro"},
		})
	}

	return root, mounts, nil
}

func sanitizeTarget(target string) string {
	clean := filepath.Clean(target)
	if clean == "/" {
		return "root"
	}
	if clean[0] == '/' {
		clean = clean[1:]
	}
	return clean
}

func envSlice(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for key, value := range env {
		out = append(out, fmt.Sprintf("%s=%s", key, value))
	}
	return out
}

type nopLogger struct{}

func (nopLogger) Debug(string, ...any) {}
func (nopLogger) Info(string, ...any)  {}
func (nopLogger) Warn(string, ...any)  {}
func (nopLogger) Error(string, ...any) {}

type fileAppender struct {
	path string
}

func (w fileAppender) Write(p []byte) (int, error) {
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Write(p)
}
