package util

import (
	"fmt"
	"runtime"

	"github.com/vishvananda/netns"
)

func WithNetNSHandle(targetNS netns.NsHandle, fn func() error) error {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

	origNS, err := netns.Get()
	if err != nil {
		return fmt.Errorf("get current netns: %w", err)
	}
	defer origNS.Close()

	if err := netns.Set(targetNS); err != nil {
		return fmt.Errorf("enter target netns: %w", err)
	}
	defer func() {
		_ = netns.Set(origNS)
	}()

	return fn()
}

func WithNetNSPath(path string, fn func() error) error {
	netns, err := netns.GetFromPath(path)
	if err != nil {
		return fmt.Errorf("get netns: %w", err)
	}
	defer netns.Close()

	return WithNetNSHandle(netns, fn)
}
