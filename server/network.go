package server

import (
	"context"
	"crypto/rand"
	"log"
	"net"

	"github.com/lbodlev888/ownvpn/crypto"
	"github.com/lbodlev888/ownvpn/proto"
	"golang.org/x/crypto/chacha20poly1305"
)

func readFromPeers(ctx context.Context) {
	buf := make([]byte, buffersize)
	for {
		n, src, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Failed to read UDP datagram: " + err.Error())
			continue
		}
		if n < 1 {
			continue
		}

		pkt := buf[:n]
		switch pkt[0] {
		case proto.MsgClientHello:
			handleHandshake(ctx, pkt, src)
		case proto.MsgData:
			handleData(pkt[1:], src)
		case proto.MsgKeepAlive:
			sendAckKeepAlive(pkt, src)
		default:
			log.Printf("Invalid packet from %s\n", net.IP(src.IP).String())
		}
	}
}

func sendAckKeepAlive(pkt []byte, src *net.UDPAddr) {
	if proto.DecodeKeepAlive(pkt, proto.MsgKeepAliveSYN) {
		if _, err := udpConn.WriteToUDP(proto.EncodeKeepAlive(proto.MsgKeepAliveACK), src); err != nil {
			log.Println("Failed to send keepalive syn:" + err.Error())
		}
		return
	}
	log.Println("Received invalid keepalive from: " + src.String())
}

func handleHandshake(ctx context.Context, pkt []byte, src *net.UDPAddr) {
	clientHello, err := proto.DecodeClientHello(pkt)
	if err != nil {
		log.Println("Invalid ClientHello: " + err.Error())
		return
	}

	allowedPeersMu.RLock()
	peerCfg, ok := allowedPeers[clientHello.Name]
	allowedPeersMu.RUnlock()
	if !ok {
		log.Printf("Unknown peer %q from %s. Dropping\n", clientHello.Name, src)
		return
	}
	
	if peerCfg.Disabled {
		log.Printf("Peer %s is disabled. Rejecting handshake", peerCfg.Name)
		return
	}

	encaps, err := crypto.ParseEncapsKey(peerCfg.EncapsKey)
	if err != nil {
		log.Printf("Could not import public key of peer %s: %v\n", peerCfg.Name, err)
		return
	}

	sharedKey2, ciphertext := encaps.Encapsulate()

	sharedKey1, err := decapsKey.Decapsulate(clientHello.PublicData)
	if err != nil {
		log.Printf("Could not decapsulate ClientHello from %s: %v\n", peerCfg.Name, err)
		return
	}

	final_key := append(sharedKey1, sharedKey2...)

	infoString, ok := ctx.Value("version").(string)
	if !ok {
		log.Println("Missing ownvpn version key in context")
		return
	}

	encryption_key, err := crypto.DeriveEncryptionKey(final_key, nil, infoString, chacha20poly1305.KeySize)
	if err != nil {
		log.Println("Failed to derive encryption key: " + err.Error())
		return
	}

	serverHelloBytes, err := proto.EncodeServerHello(proto.ServerHello{PublicData: ciphertext})
	if err != nil {
		log.Println("Failed to encode ServerHello: " + err.Error())
		return
	}

	if _, err := udpConn.WriteToUDP(serverHelloBytes, src); err != nil {
		log.Println("Failed to send ServerHello: " + err.Error())
		return
	}

	peer := &peer{
		Addr:       src,
		VirtualIP:  net.ParseIP(peerCfg.VirtualIP),
		SessionKey: encryption_key,
	}

	peersMu.Lock()
	if old, ok := peersByIP[peerCfg.VirtualIP]; ok {
		delete(peersByAddr, old.Addr.String())
		log.Printf("Replacing existing session for %s (%s -> %s)\n", peerCfg.Name, old.Addr, src)
	}
	peersByIP[peerCfg.VirtualIP] = peer
	peersByAddr[src.String()] = peer
	peersMu.Unlock()

	log.Printf("Peer connected: %s -> %s (from %s)\n", peerCfg.Name, peerCfg.VirtualIP, src)
}

func handleData(payload []byte, src *net.UDPAddr) {
	peersMu.RLock()
	peer, ok := peersByAddr[src.String()]
	peersMu.RUnlock()
	if !ok || peer.disabled {
		// unknown source; ignore (could be stale or spoofed)
		return
	}

	if len(payload) < chacha20poly1305.NonceSize {
		return
	}

	cipher, err := chacha20poly1305.New(peer.SessionKey)
	if err != nil {
		log.Println("Failed to init cipher: " + err.Error())
		return
	}

	nonce := payload[:chacha20poly1305.NonceSize]
	ciphertext := payload[chacha20poly1305.NonceSize:]

	frame, err := cipher.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("Failed to decrypt frame from %s: %v\n", src.String(), err.Error())
		return
	}

	if len(frame) < 20 || frame[0] >> 4 != 4 {
		return
	}

	dstIP := net.IP(frame[16:20]).String()

	peersMu.RLock()
	dstPeer, ok := peersByIP[dstIP]
	peersMu.RUnlock()
	if !ok {
		iface.Write(frame)
		return
	}

	sendEncrypted(dstPeer, frame)
}

func readFromIface(ctx context.Context) {
	packet := make([]byte, buffersize)
	for {
		n, err := iface.Read(packet)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Failed to read from iface: " + err.Error())
			continue
		}
		actualData := packet[:n]

		if len(actualData) < 20 || actualData[0] >> 4 != 4 {
			continue
		}

		dstIP := net.IP(actualData[16:20]).String()
		peersMu.RLock()
		peer, ok := peersByIP[dstIP]
		peersMu.RUnlock()
		if !ok || peer.disabled {
			continue
		}

		sendEncrypted(peer, actualData)
	}
}

func sendEncrypted(peer *peer, frame []byte) {
	cipher, err := chacha20poly1305.New(peer.SessionKey)
	if err != nil {
		log.Println("Failed to init cipher: " + err.Error())
		return
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	rand.Read(nonce)

	out := make([]byte, 0, 1+len(nonce)+len(frame)+chacha20poly1305.Overhead)
	out = append(out, proto.MsgData)
	out = append(out, nonce...)
	out = cipher.Seal(out, nonce, frame, nil)

	if _, err := udpConn.WriteToUDP(out, peer.Addr); err != nil {
		log.Println("Failed to send to peer " + peer.Addr.String() + ": " + err.Error())
	}
}
