package server

import (
	"context"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"
	"vpn/config"
	"vpn/models"
	"vpn/network"
	"vpn/proto"
	"vpn/tunif"

	"github.com/lbodlev888/go-spake"
	"github.com/songgao/water"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	BUFFERSIZE = 1500
)

var (
	peersMu sync.RWMutex
	peers = make(map[string]models.Peer)
	allowedPeers map[string]config.PeerConfig
	wg sync.WaitGroup
	virtualIP string
	iface *water.Interface
)

func RunServer(ctx context.Context, cfg *config.ServerConfig, stop context.CancelFunc) {
	virtualIP = cfg.VirtualIP
	allowedPeers = make(map[string]config.PeerConfig)
	for _, p := range cfg.Peers {
		allowedPeers[p.Name] = p
	}

	var err error
	iface, err = tunif.SetupInterface(fmt.Sprintf("%s/%d", cfg.VirtualIP, cfg.Subnet))
	if err != nil {
		log.Fatalln("Could not create tun interface: " + err.Error())
	}

	listener, err := net.Listen("tcp", cfg.BindAddress)
	if err != nil {
		log.Fatalln("Could not bind address: " + err.Error())
	}
	defer listener.Close()

	log.Printf("Server listening on %s (VPN IP: %s/%d)", cfg.BindAddress, cfg.VirtualIP, cfg.Subnet)

	wg.Go(func() { acceptPeers(ctx, listener) })
	wg.Go(func() { processLocalIface(iface) })

	wg.Go(func(){
		<-ctx.Done()
		iface.Close()
		listener.Close()

		peersMu.RLock()
		for _, p := range peers {
			p.Conn.Close()
		}
		peersMu.RUnlock()
	})

	wg.Wait()
}

func acceptPeers(ctx context.Context, l net.Listener) {
	for {
		client, err := l.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Println("Failed to accept client: " + err.Error())
			continue
		}
		wg.Go(func() { handleClient(client) })
	}
}

func processLocalIface(iface *water.Interface) {
	packet := make([]byte, BUFFERSIZE)
	nonce := make([]byte, chacha20poly1305.NonceSize)

	for {
		n, err := iface.Read(packet)
		if err != nil {
			log.Println("Failed to read from iface:" + err.Error())
			return
		}
		actualData := packet[:n]

		if len(actualData) < 20 {
			continue //invalid IPv4 packet
		}

		if actualData[0] >> 4 != 4 {
			continue //invalid or IPv6, currently handling only IPv4
		}

		dstIP := net.IP(actualData[16:20]).String()
		peersMu.RLock()
		peer, ok := peers[dstIP]
		peersMu.RUnlock()
		if !ok {
			continue
		}

		cipher, err := chacha20poly1305.New(peer.SessionKey)
		if err != nil {
			log.Println("Failed to init cipher: " + err.Error())
			break
		}

		rand.Read(nonce)
		enc_frame := cipher.Seal(nil, nonce, actualData, nil)
		final_packet := append(nonce, enc_frame...)
		network.WriteFrame(peer.Conn, final_packet)
	}
}

func handleClient(conn net.Conn) {
	defer conn.Close()
	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	var clientHello proto.ClientHello
	if err := dec.Decode(&clientHello); err != nil {
		log.Println("Could not read clientHello: " + err.Error())
		return
	}

	peerCfg, ok := allowedPeers[clientHello.Name]
	if !ok {
		log.Println("Invalid peer. Dropping connection")
		return
	}

	peersMu.RLock()
	_, exists := peers[peerCfg.VirtualIP]
	peersMu.RUnlock()
	if exists {
		log.Println("Peer already connected. Dropping the connection")
		return
	}

	var spake spake.Spake
	spake.Role = true
	msg, err := spake.Start([]byte(peerCfg.Password))
	if err != nil {
		fmt.Println("Failed to init spake: " + err.Error())
		return
	}

	if err := enc.Encode(proto.ServerHello{
		PublicKey: msg,
	}); err != nil {
		log.Println("Failed to send serverHello: " + err.Error())
		return
	}

	shared, err := spake.Finish(clientHello.PublicKey)
	if err != nil {
		log.Println("Failed to derive shared secret: " + err.Error())
		return
	}

	encryption_key, err := hkdf.Key(sha256.New, shared, nil, "own_vpn0.0.1", chacha20poly1305.KeySize)
	if err != nil {
		log.Println("Failed to derive encryption key: " + err.Error())
		return
	}

	peer := models.Peer{
		Conn: conn,
		VirtualIP: net.ParseIP(peerCfg.VirtualIP),
		SessionKey: encryption_key,
	}

	peersMu.Lock()
	peers[peerCfg.VirtualIP] = peer
	peersMu.Unlock()

	log.Printf("Peer connected: %s -> %s\n", peerCfg.Name, peerCfg.VirtualIP)

	handleFrames(peer)

	log.Printf("Peer disconnected: %s -> %s\n", peerCfg.Name, peerCfg.VirtualIP)
	peersMu.Lock()
	delete(peers, peerCfg.VirtualIP)
	peersMu.Unlock()
}

func handleFrames(peer models.Peer) {
	readCipher, err := chacha20poly1305.New(peer.SessionKey)
	if err != nil {
		log.Println("Failed to init cipher: " + err.Error())
		return
	}

	for {
		encrypted_frame, err := network.ReadFrame(peer.Conn)
		if err != nil {
			log.Printf("Failed to read from peer %s with error %v: ", peer.VirtualIP, err)
			return
		}

		nonce := encrypted_frame[:chacha20poly1305.NonceSize]
		encrypted_frame = encrypted_frame[chacha20poly1305.NonceSize:]

		frame, err := readCipher.Open(nil, nonce, encrypted_frame, nil)
		if err != nil {
			log.Println("Failed to decrypt: " + err.Error())
			continue
		}

		if len(frame) < 20 {
			continue //invalid IPv4 packet
		}
		
		if frame[0] >> 4 != 4 {
			continue //invalid or IPv6 packet, currently handling only IPv4
		}

		dstIP := net.IP(frame[16:20]).String()
		if virtualIP == dstIP {
			iface.Write(frame)
			continue
		}
		peersMu.RLock()
		peer, ok := peers[dstIP]
		peersMu.RUnlock()
		if !ok {
			continue
		}
		cipher, err := chacha20poly1305.New(peer.SessionKey)
		if err != nil {
			log.Println("Failed to init cipher: " + err.Error())
			break
		}

		clear(nonce)
		rand.Read(nonce)
		new_encframe := cipher.Seal(nil, nonce, frame, nil)
		final_packet := append(nonce, new_encframe...)
		network.WriteFrame(peer.Conn, final_packet)
	}
}
