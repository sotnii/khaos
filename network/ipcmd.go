package network

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

type Commander interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
}

type ExecCommander struct{}

func (ExecCommander) Run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		errText := strings.TrimSpace(stderr.String())
		if errText == "" {
			errText = err.Error()
		}
		return "", fmt.Errorf("%s %v: %s", name, args, errText)
	}

	return stdout.String(), nil
}

type IPCmd struct {
	cmd Commander
}

func NewIPCmd(cmd Commander) *IPCmd {
	return &IPCmd{cmd: cmd}
}

func (c *IPCmd) LinkStatus(ctx context.Context, name string) (exists bool, up bool, err error) {
	out, err := c.cmd.Run(ctx, "ip", "link", "show", name)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") || strings.Contains(err.Error(), "Cannot find device") {
			return false, false, nil
		}
		return false, false, err
	}
	return true, strings.Contains(out, "state UP"), nil
}

func (c *IPCmd) AddBridge(ctx context.Context, name string) error {
	_, err := c.cmd.Run(ctx, "ip", "link", "add", name, "type", "bridge")
	return err
}

func (c *IPCmd) BringLinkUp(ctx context.Context, name string) error {
	_, err := c.cmd.Run(ctx, "ip", "link", "set", name, "up")
	return err
}

func (c *IPCmd) AddNamespace(ctx context.Context, name string) error {
	_, err := c.cmd.Run(ctx, "ip", "netns", "add", name)
	return err
}

func (c *IPCmd) DeleteNamespace(ctx context.Context, name string) error {
	_, err := c.cmd.Run(ctx, "ip", "netns", "del", name)
	return err
}

func (c *IPCmd) AddVethPair(ctx context.Context, veth, peer string) error {
	_, err := c.cmd.Run(ctx, "ip", "link", "add", veth, "type", "veth", "peer", "name", peer)
	return err
}

func (c *IPCmd) MoveToNamespace(ctx context.Context, iface, namespace string) error {
	_, err := c.cmd.Run(ctx, "ip", "link", "set", iface, "netns", namespace)
	return err
}

func (c *IPCmd) SetMaster(ctx context.Context, iface, master string) error {
	_, err := c.cmd.Run(ctx, "ip", "link", "set", iface, "master", master)
	return err
}

func (c *IPCmd) NamespaceLinkUp(ctx context.Context, namespace, iface string) error {
	_, err := c.cmd.Run(ctx, "ip", "netns", "exec", namespace, "ip", "link", "set", iface, "up")
	return err
}

func (c *IPCmd) NamespaceAddrAdd(ctx context.Context, namespace, iface, addr string) error {
	_, err := c.cmd.Run(ctx, "ip", "netns", "exec", namespace, "ip", "addr", "add", addr, "dev", iface)
	return err
}
