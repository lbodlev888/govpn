package tunif

import (
	"fmt"
	"strconv"

	"github.com/songgao/water"
)

func newTUN(localAddr string) (*water.Interface, error) {
	return water.New(water.Config{
		DeviceType:             water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{Name: "bvpn%d"},
	})
}

func configureInterface(ifaceName, localAddr string) error {
	if err := run("ip", "link", "set", "dev", ifaceName, "mtu", strconv.Itoa(MTU)); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	if err := run("ip", "addr", "add", localAddr, "dev", ifaceName); err != nil {
		return fmt.Errorf("failed to set local IP address: %w", err)
	}

	if err := run("ip", "link", "set", "dev", ifaceName, "up"); err != nil {
		return fmt.Errorf("failed to start: %w", err)
	}

	return nil
}

func addRoute(ifaceName, subnet string) error {
	return run("ip", "route", "add", subnet, "dev", ifaceName)
}

func addTunnelRoutes(ifaceName string) error {
	if err := addRoute(ifaceName, "0.0.0.0/1"); err != nil {
		return err
	}

	return addRoute(ifaceName, "128.0.0.0/1")
}

func addBypassRoute(endpoint, gw string) error {
	return run("ip", "route", "add", endpoint, "via", gw)
}

func delBypassRoute(endpoint string) error {
	return run("ip", "route", "delete", endpoint)
}
