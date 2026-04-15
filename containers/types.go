package containers

import (
	"context"
	"time"

	"github.com/sotnii/pakostii/network"
	"github.com/sotnii/pakostii/spec"
)

const (
	DefaultSocket      = "/run/containerd/containerd.sock"
	DefaultNamespace   = "pakostii"
	DefaultSnapshotter = "overlayfs"
)

type LaunchRequest struct {
	ID          string
	Name        string
	NodeID      string
	ImageRef    string
	NetNSPath   string
	Hostname    string
	Env         map[string]string
	Files       map[string]string
	StartDelay  time.Duration
	Readiness   spec.Probe
	NamespaceIP string
}

type RunningContainer struct {
	ID          string
	Name        string
	NodeID      string
	SnapshotKey string
	BundleDir   string
	IO          ContainerIO
}

type ContainerIO struct {
	Dir    string
	Stdout string
	Stderr string
}

type ExecResult struct {
	ExitCode uint32
	Stdout   string
	Stderr   string
}

type Event struct {
	ContainerID string
	ExecID      string
	ExitCode    uint32
}

type Manager interface {
	RunContainer(ctx context.Context, req LaunchRequest) (*RunningContainer, error)
	TeardownContainer(ctx context.Context, ctr RunningContainer) error
	ExecInContainer(ctx context.Context, containerID string, argv []string) (*ExecResult, error)
	ObserveEvents(ctx context.Context) (<-chan Event, <-chan error, error)
	Close() error
}

type NetworkNamespace = network.Namespace
