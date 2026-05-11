package server

import (
	"context"
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/lbodlev888/ownvpn/config"
	"github.com/lbodlev888/ownvpn/models"
	"github.com/lbodlev888/ownvpn/network"
	"github.com/lbodlev888/ownvpn/proto"
	"github.com/lbodlev888/ownvpn/tunif"
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
	decapsKey *mlkem.DecapsulationKey768
	iface *water.Interface
)

func RunServer(ctx context.Context, cfg *config.ServerConfig, stop context.CancelFunc) {
	raw_decaps, err := base64.StdEncoding.DecodeString(cfg.DecapsKey)
	if err != nil {
		log.Fatalln("Could not decode private key of server: " + err.Error())
	}

	decapsKey, err = mlkem.NewDecapsulationKey768(raw_decaps)
	if err != nil {
		log.Fatalln("Could not import private key of server: " + err.Error())
	}

	virtualIP = cfg.VirtualIP

	allowedPeers = make(map[string]config.PeerConfig)
	for _, p := range cfg.Peers {
		allowedPeers[p.Name] = p
	}

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
		wg.Go(func() { handleClient(ctx, client) })
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

func handleClient(ctx context.Context, conn net.Conn) {
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

	raw_encaps, err := base64.StdEncoding.DecodeString(peerCfg.EncapsKey)
	if err != nil {
		log.Printf("Coult not decode encaps key of peer %s: %v\n", peerCfg.Name, err)
		return
	}

	encaps, err := mlkem.NewEncapsulationKey768(raw_encaps)
	if err != nil {
		log.Printf("Could not import public key of peer %s: %v\n", peerCfg.Name, err)
		return
	}

	sharedKey2, ciphertext := encaps.Encapsulate()

	if err := enc.Encode(proto.ServerHello{
		PublicData: ciphertext,
	}); err != nil {
		log.Println("Failed to send serverHello: " + err.Error())
		return
	}

	sharedKey1, err := decapsKey.Decapsulate(clientHello.PublicData)
	if err != nil {
		log.Printf("Could not decrypt clientHello from %s: %v\n", peerCfg.Name, err)
	}

	final_key := append(sharedKey1, sharedKey2...)

	infoString, ok := ctx.Value("version").(string)
	if !ok {
		log.Fatalln("Missing ownvpn version key in context")
	}

	encryption_key, err := hkdf.Key(sha256.New, final_key, nil, infoString, chacha20poly1305.KeySize)
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
