package tunif

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/songgao/water"
)

const (
	MTU = "1420"
)

func SetupInterface(localAddr string) (*water.Interface, error) {
	iface, err := water.New(water.Config{DeviceType: water.TUN, PlatformSpecificParams: water.PlatformSpecificParams{Name: "bvpn0"}})
	if err != nil {
		panic("Failed to init interface:" + err.Error())
	}

	err = runIP("link", "set", "dev", iface.Name(), "mtu", MTU)
	if err != nil { return nil, fmt.Errorf("Failed to set MTU: %w", err) }

	err = runIP("addr", "add", localAddr, "dev", iface.Name())
	if err != nil { return nil, fmt.Errorf("Failed to local IP address: %w", err) }

	err = runIP("link", "set", "dev", iface.Name(), "up")
	if err != nil { return nil, fmt.Errorf("Failed to start: %w", err) }

	return iface, nil
}

func runIP(args ...string) error {
	cmd := exec.Command("ip", args...)
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	
	return cmd.Run()
}
