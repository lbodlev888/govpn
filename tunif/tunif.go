package tunif

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"time"

	"github.com/jackpal/gateway"
	"github.com/songgao/water"
	"github.com/vishvananda/netlink"
)

const MTU = 1420

func SetupInterface(localAddr string) (*water.Interface, error) {
	if _, _, err := net.ParseCIDR(localAddr); err != nil {
		return nil, fmt.Errorf("invalid interface address %q: %w", localAddr, err)
	}

	iface, err := newTUN(localAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to init interface: %w", err)
	}

	if err := configureInterface(iface.Name(), localAddr); err != nil {
		_ = iface.Close()
		return nil, err
	}

	return iface, nil
}

func SetupRoutes(ifaceName string, routes []string) error {
	for _, route := range routes {
		if err := addRoute(ifaceName, route); err != nil {
			return fmt.Errorf("SetupRoutes: failed setting route %q: %w", route, err)
		}
	}

	return nil
}

func SetupFullTunnel(endpoint, ifaceName string) error {
	if err := addTunnelRoutes(ifaceName); err != nil {
		return fmt.Errorf("failed to route traffic into the tunnel: %w", err)
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

func EnsureBypassRoute(ctx context.Context, endpointAddr string, rehandshakeCh chan struct{}) error {
	doneCh := make(chan struct{})
	routesCh := make(chan netlink.RouteUpdate, 10)
	if err := netlink.RouteSubscribe(routesCh, doneCh); err != nil {
		return fmt.Errorf("failed to subscribe to route update: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			close(doneCh)
			return nil
		case <-routesCh:
			log.Println("updating routes")
			if gw, err := gateway.DiscoverGateway(); err != nil {
				log.Println("Failed extracting default gateway: " + err.Error())
				time.Sleep(time.Second / 2)
			} else {
				addBypassRoute(endpointAddr, gw.String())
				rehandshakeCh <- struct{}{}
			}
		}
	}
}

func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)

	return cmd.Run()
}
