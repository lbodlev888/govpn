package tunif

import (
	"fmt"
	"net"
	"os"
	"os/exec"

	"github.com/jackpal/gateway"
	"github.com/songgao/water"
)

const MTU = 1420

func SetupInterface(localAddr string) (*water.Interface, error) {
	if _, _, err := net.ParseCIDR(localAddr); err != nil {
		return nil, fmt.Errorf("Invalid interface address %q: %w", localAddr, err)
	}

	iface, err := newTUN(localAddr)
	if err != nil {
		return nil, fmt.Errorf("Failed to init interface: %w", err)
	}

	if err := configureInterface(iface.Name(), localAddr); err != nil {
		iface.Close()
		return nil, err
	}

	return iface, nil
}

func SetupFullTunnel(endpoint, ifaceName string) error {
	if err := addTunnelRoutes(ifaceName); err != nil {
		return fmt.Errorf("Failed to route traffic into the tunnel: %w", err)
	}

	ip, err := gateway.DiscoverGateway()
	if err != nil {
		return err
	}
	gatewayAddr := ip.String()

	return addBypassRoute(endpoint, gatewayAddr)
}

func ClearFullTunnel(endpoint string) error {
	return delBypassRoute(endpoint)
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout

	return cmd.Run()
}
