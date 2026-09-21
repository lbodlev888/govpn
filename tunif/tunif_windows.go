package tunif

import (
	"fmt"
	"net"
	"strconv"

	"github.com/songgao/water"
)

const adapterName = "ownvpn"

func newTUN(localAddr string) (*water.Interface, error) {
	return water.New(water.Config{
		DeviceType: water.TUN,
		PlatformSpecificParams: water.PlatformSpecificParams{
			Name:    adapterName,
			Network: localAddr,
		},
	})
}

func configureInterface(ifaceName, localAddr string) error {
	addr, mask, err := splitCIDR(localAddr)
	if err != nil {
		return err
	}

	if err := run("netsh", "interface", "ipv4", "set", "address",
		"name=" + ifaceName, "source=static", "address="+addr, "mask="+mask, "gateway=none"); err != nil {
		return fmt.Errorf("failed to set local IP address: %w", err)
	}

	if err := run("netsh", "interface", "ipv4", "set", "subinterface", ifaceName,
		"mtu="+strconv.Itoa(MTU), "store=active"); err != nil {
		return fmt.Errorf("failed to set MTU: %w", err)
	}

	return nil
}

func addRoute(ifaceName, subnet string) error {
	return run("netsh", "interface", "ipv4", "add", "route",
		"prefix=" + subnet, "interface=" + ifaceName, "store=active")
}

func addTunnelRoutes(ifaceName string) error {
	if err := addRoute(ifaceName, "0.0.0.0/1"); err != nil {
		return err
	}

	return addRoute(ifaceName, "128.0.0.0/1")
}

func addBypassRoute(endpoint, gw string) error {
	return run("route", "add", endpoint, "mask", "255.255.255.255", gw)
}

func delBypassRoute(endpoint string) error {
	return run("route", "delete", endpoint)
}

func splitCIDR(cidr string) (addr, mask string, err error) {
	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return "", "", err
	}

	if len(ipnet.Mask) != net.IPv4len {
		return "", "", fmt.Errorf("%q is not an IPv4 address", cidr)
	}

	return ip.String(), net.IP(ipnet.Mask).String(), nil
}
