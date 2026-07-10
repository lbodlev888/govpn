package client

import (
	"context"
	"crypto/mlkem"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lbodlev888/ownvpn/config"
	"github.com/lbodlev888/ownvpn/crypto"
	"github.com/lbodlev888/ownvpn/proto"
	"github.com/lbodlev888/ownvpn/tunif"
	"github.com/songgao/water"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	buffersize        = 2048
	handshake_timeout = 5 * time.Minute
)

var (
	iface          *water.Interface
	s2cKey, c2sKey atomic.Pointer[[chacha20poly1305.KeySize]byte]
	lastNonceOut   atomic.Uint64
	cipherChan     chan struct{}
	serverAddr     *net.UDPAddr
	conn           *net.UDPConn
	cfg            *config.PeerConfig
	decaps         *mlkem.DecapsulationKey768
	encaps         *mlkem.EncapsulationKey768
	filter         proto.Filter
)

func Init(config config.PeerConfig) error {
	cipherChan = make(chan struct{})
	cfg = &config

	if config.Endpoint == "" {
		return fmt.Errorf("Init: missing endpoint")
	}

	var err error
	iface, err = tunif.SetupInterface(fmt.Sprintf("%s/%d", config.VirtualIP, config.Subnet))
	if err != nil {
		return fmt.Errorf("Could not create tun interface: %w", err)
	}

	if config.FullTunnel {
		if err := tunif.SetupFullTunnel(strings.Split(config.Endpoint, ":")[0], iface.Name()); err != nil {
			return fmt.Errorf("Init: failed to setup full tunnel: %w", err)
		}
	}

	decaps, err = crypto.ParseDecapsKey(config.DecapsKey)
	if err != nil {
		return fmt.Errorf("Could not import private key: %w", err)
	}

	encaps, err = crypto.ParseEncapsKey(config.EncapsKey)
	if err != nil {
		return fmt.Errorf("Could not import public key: %w", err)
	}

	serverAddr, err = net.ResolveUDPAddr("udp", config.Endpoint)
	if err != nil {
		return fmt.Errorf("Could not resolve endpoint: %w", err)
	}

	lAddr, _ := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	conn, err = net.ListenUDP("udp", lAddr)
	if err != nil {
		return fmt.Errorf("Failed to connect to server: %w", err)
	}

	log.Println("Peer name: " + config.Name)

	return nil
}

func Run(ctx context.Context) {
	var wg sync.WaitGroup

	wg.Go(func() { rehandshakeLoop(ctx) })
	wg.Go(func() { keepaliveLoop(ctx) })
	wg.Go(func() { udpReadLoop(ctx) })
	wg.Go(func() { tunReadLoop(ctx) })

	wg.Go(func() {
		<-ctx.Done()
		log.Println("Received stop signal. Closing everything")
		if cfg.FullTunnel {
			if err := tunif.ClearFullTunnel(strings.Split(cfg.Endpoint, ":")[0]); err != nil {
				log.Println("Failed to clear full tunnel: " + err.Error())
			}
		}
		conn.Close()
		iface.Close()
	})

	wg.Wait()
}
