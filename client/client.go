package client

import (
	"context"
	"crypto/ed25519"
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
	iface           *water.Interface
	s2cKey, c2sKey  atomic.Pointer[[chacha20poly1305.KeySize]byte]
	lastNonceOut    atomic.Uint64
	cipherChan      chan struct{}
	serverHelloChan chan []byte
	serverAddr      *net.UDPAddr
	conn            *net.UDPConn
	cfg             *config.PeerConfig
	privKey         ed25519.PrivateKey
	pubKey          ed25519.PublicKey
	filter          proto.Filter
)

func Init(config config.PeerConfig) error {
	cipherChan = make(chan struct{})
	serverHelloChan = make(chan []byte, 1)
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
		endpoint, _, found := strings.Cut(config.Endpoint, ":")
		if !found {
			return fmt.Errorf("Init: invalid endpoint: should be <address>:<port>")
		}

		if err := tunif.SetupFullTunnel(endpoint, iface.Name()); err != nil {
			tunif.ClearFullTunnel(endpoint)
			return fmt.Errorf("Init: failed to setup full tunnel: %w", err)
		}
	}

	privKey, err = crypto.ParsePrivateKey(config.PrivateKey)
	if err != nil {
		return fmt.Errorf("Could not import private key: %w", err)
	}

	pubKey, err = crypto.ParsePublicKey(config.PublicKey)
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

	log.Println("Initiated with peer name: " + config.Name)

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
