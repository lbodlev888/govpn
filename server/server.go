package server

import (
	"context"
	"crypto/mlkem"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/lbodlev888/ownvpn/config"
	"github.com/lbodlev888/ownvpn/crypto"
	"github.com/lbodlev888/ownvpn/tunif"
	"github.com/songgao/water"
)

const (
	buffersize = 2048
)

var (
	peersMu      sync.RWMutex
	peersByIP    = make(map[string]*peer) //key is virtual IP
	peersByAddr  = make(map[string]*peer) //key is public IP
	allowedPeersMu sync.RWMutex
	allowedPeers = make(map[string]config.PeerConfig) //key is name of peer
	wg           sync.WaitGroup
	decapsKey    *mlkem.DecapsulationKey768
	iface        *water.Interface
	udpConn      *net.UDPConn
	cfg config.ServerConfig
)

func Init(serverConfiguration config.ServerConfig) error {
	cfg = serverConfiguration

	var err error
	decapsKey, err = crypto.ParseDecapsKey(cfg.DecapsKey)
	if err != nil {
		return fmt.Errorf("Init: could not import private key: %w", err)
	}

	loadAllowedPeers()

	iface, err = tunif.SetupInterface(fmt.Sprintf("%s/%d", cfg.VirtualIP, cfg.Subnet))
	if err != nil {
		return fmt.Errorf("Init: could not create tun interface: %w", err)
	}

	udpAddr, err := net.ResolveUDPAddr("udp", cfg.BindAddress)
	if err != nil {
		return fmt.Errorf("Init: could not resolve bind address: %w", err)
	}

	udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("Init: could not bind UDP socket: %w", err)
	}

	return nil
}

func Run(ctx context.Context) {
	log.Printf("Server listening on %s (UDP, VPN IP: %s/%d)", cfg.BindAddress, cfg.VirtualIP, cfg.Subnet)

	wg.Go(func() { readFromPeers(ctx) })
	wg.Go(func() { readFromIface(ctx) })

	wg.Go(func() {
		<-ctx.Done()
		iface.Close()
		udpConn.Close()
	})

	wg.Wait()
}

func NewPeer(peer config.PeerConfig) error {
	allowedPeersMu.Lock()
	defer allowedPeersMu.Unlock()

	if err := checkEncapsulation(peer.EncapsKey); err != nil {
		return fmt.Errorf("NewPeer: invalid encapsulation key: %w", err)
	}

	allowedPeers[peer.Name] = peer

	return nil
}

func GetAllPeers() []config.PeerConfig {
	allowedPeersMu.RLock()
	defer allowedPeersMu.RUnlock()

	out := make([]config.PeerConfig, 0, len(allowedPeers))
	for _, peer := range allowedPeers {
		out = append(out, peer)
	}

	return out
}

func RemovePeer(name string) {
	allowedPeersMu.Lock()
	peersMu.Lock()
	defer func() {
		allowedPeersMu.Unlock()
		peersMu.Unlock()
	}()

	peer, ok := allowedPeers[name]
	if !ok {
		return
	}
	delete(allowedPeers, name)

	virtualPeer, ok := peersByIP[peer.VirtualIP]
	if !ok {
		return
	}
	delete(peersByIP, peer.VirtualIP)

	addr := virtualPeer.Addr.String()
	_, ok = peersByAddr[addr]
	if !ok {
		return
	}

	delete(peersByAddr, addr)
}

func EnablePeer(name string) {
	allowedPeersMu.Lock()
	defer allowedPeersMu.Unlock()
	peer, ok := allowedPeers[name]
	if !ok {
		return
	}
	peer.Disabled = false
	allowedPeers[name] = peer

	peersMu.Lock()
	defer peersMu.Unlock()

	virtualPeer, ok := peersByIP[peer.VirtualIP]
	if !ok {
		return
	}
	virtualPeer.disabled = false

	logicalPeer, ok := peersByAddr[virtualPeer.Addr.String()]
	if !ok {
		return
	}
	logicalPeer.disabled = false
}

func DisablePeer(name string) {
	allowedPeersMu.Lock()
	defer allowedPeersMu.Unlock()
	peer, ok := allowedPeers[name]
	if !ok {
		log.Println("allowed peer not found")
		return
	}
	peer.Disabled = true
	allowedPeers[name] = peer

	peersMu.Lock()
	defer peersMu.Unlock()
	virtualPeer, ok := peersByIP[peer.VirtualIP]
	if !ok {
		log.Println("virtual peer not found")
		return
	}
	virtualPeer.disabled = true

	logicalPeer, ok := peersByAddr[virtualPeer.Addr.String()]
	if !ok {
		log.Println("logical peer not found")
		return
	}
	logicalPeer.disabled = true
}

func MarshalPeerSettings() ([]byte, error) {
	cfg.Peers = nil
	cfg.Peers = make([]config.PeerConfig, 0, len(allowedPeers))

	for _, peer := range allowedPeers {
		cfg.Peers = append(cfg.Peers, peer)
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		return nil, fmt.Errorf("MarshalPeerSettings: %w", err)
	}

	return data, nil
}
