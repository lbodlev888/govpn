package server

import (
	"context"
	"crypto/mlkem"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/lbodlev888/govpn/crypto"
	"github.com/lbodlev888/govpn/proto"
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
			handleHandshake(pkt, src)
		case proto.MsgData:
			handleData(pkt, src)
		case proto.MsgKeepAliveSYN:
			handleKeepAlive(pkt, src)
		case proto.MsgClientConfirm:
			handleConfirm(pkt, src)
		default:
			log.Printf("Invalid packet from %s\n", net.IP(src.IP).String())
		}
	}
}

func handleKeepAlive(packet []byte, src *net.UDPAddr) {
	peersMu.RLock()
	peer, ok := peersByAddr[src.String()]
	peersMu.RUnlock()
	if !ok {
		log.Println("Got keepalive from unexisting peer")
		return
	}

	if _, err := parseEncrypted(peer, packet); err != nil {
		log.Println("handleKeepAlive: " + err.Error())
		return
	}

	sendEncrypted(peer, proto.MsgKeepAliveACK, nil)
}

func handleConfirm(packet []byte, src *net.UDPAddr) {
	pendingMu.Lock()
	pend, ok := pendingByAddr[src.String()]
	pendingMu.Unlock()
	if !ok {
		return
	}

	if _, err := parseEncrypted(pend.peer, packet); err != nil {
		return
	}

	pendingMu.Lock()
	delete(pendingByAddr, src.String())
	pendingMu.Unlock()

	peersMu.Lock()
	if old, ok := peersByIP[pend.virtualIP]; ok && old.Addr.String() != src.String() {
		delete(peersByAddr, old.Addr.String())
	}
	peersByIP[pend.virtualIP] = pend.peer
	peersByAddr[src.String()] = pend.peer
	peersMu.Unlock()

	log.Printf("Peer confirmed: %s -> %s (from %s)\n", pend.name, pend.virtualIP, src)
}

func handleHandshake(pkt []byte, src *net.UDPAddr) {
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

	pubKey, err := crypto.ParsePublicKey(peerCfg.PublicKey)
	if err != nil {
		log.Printf("Could not import public key of peer %s: %v\n", peerCfg.Name, err)
		return
	}

	if !crypto.CheckClientHello(pubKey, clientHello) {
		log.Printf("Invalid signature on client hello from %s\n", peerCfg.Name)
		return
	}

	encaps, err := mlkem.NewEncapsulationKey768(clientHello.EncapsKey)
	if err != nil {
		log.Println("Invalid encapsulation key: " + err.Error())
		return
	}

	sharedKey, ciphertext := encaps.Encapsulate()

	serverHello := proto.ServerHello{Ciphertext: ciphertext}
	if err := crypto.SignServerHello(privKey, &serverHello); err != nil {
		log.Println("Failed to sign server hello: " + err.Error())
		return
	}

	serverHelloBytes, err := proto.EncodeServerHello(serverHello)
	if err != nil {
		log.Println("Failed to encode ServerHello: " + err.Error())
		return
	}

	if _, err := udpConn.WriteToUDP(serverHelloBytes, src); err != nil {
		log.Println("Failed to send ServerHello: " + err.Error())
		return
	}

	c2sKey, err := crypto.DeriveEncryptionKey(sharedKey, nil, "c2s_" + peerCfg.Name, chacha20poly1305.KeySize)
	if err != nil {
		log.Println("Failed to derive c2s encryption key: " + err.Error())
		return
	}

	s2cKey, err := crypto.DeriveEncryptionKey(sharedKey, nil, "s2c_" + peerCfg.Name, chacha20poly1305.KeySize)
	if err != nil {
		log.Println("Failed to derive s2c encryption key: " + err.Error())
		return
	}

	newPeer := &peer{
		Addr:      src,
		VirtualIP: net.ParseIP(peerCfg.VirtualIP),
		s2cKey:    s2cKey,
		c2sKey:    c2sKey,
	}

	pendingMu.Lock()
	for k, p := range pendingByAddr {
		if time.Since(p.createdAt) > 5 * time.Second {
			delete(pendingByAddr, k)
		}
	}
	pendingByAddr[src.String()] = &pendingSession{
		peer:      newPeer,
		name:      peerCfg.Name,
		virtualIP: peerCfg.VirtualIP,
		createdAt: time.Now(),
	}
	pendingMu.Unlock()
}

func handleData(packet []byte, src *net.UDPAddr) {
	peersMu.RLock()
	peer, ok := peersByAddr[src.String()]
	peersMu.RUnlock()
	if !ok || peer.disabled {
		return
	}

	frame, err := parseEncrypted(peer, packet)
	if err != nil {
		log.Println("handleData: " + err.Error())
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
		_, _ = iface.Write(frame)
		return
	}

	sendEncrypted(dstPeer, proto.MsgData, frame)
}

func readFromIface(ctx context.Context) {
	buf := make([]byte, buffersize)
	for {
		n, err := iface.Read(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Failed to read from iface: " + err.Error())
			continue
		}
		packet := buf[:n]

		if len(packet) < 20 || packet[0] >> 4 != 4 {
			continue
		}

		dstIP := net.IP(packet[16:20]).String()
		peersMu.RLock()
		peer, ok := peersByIP[dstIP]
		peersMu.RUnlock()
		if !ok || peer.disabled {
			continue
		}

		sendEncrypted(peer, proto.MsgData, packet)
	}
}

func sendEncrypted(peer *peer, messageType byte, frame []byte) {
	cipher, err := chacha20poly1305.New(peer.s2cKey)
	if err != nil {
		log.Println("Failed to init cipher: " + err.Error())
		return
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce, peer.lastNonceOut.Add(1))

	out := make([]byte, 1, 1+chacha20poly1305.NonceSize+len(frame)+chacha20poly1305.Overhead)
	out[0] = messageType
	out = append(out, nonce...)
	out = cipher.Seal(out, nonce, frame, out[:13])

	if _, err := udpConn.WriteToUDP(out, peer.Addr); err != nil {
		log.Println("Failed to send to peer " + peer.Addr.String() + ": " + err.Error())
	}
}

func parseEncrypted(peer *peer, packet []byte) ([]byte, error) {
	if len(packet) < 1 + chacha20poly1305.NonceSize {
		return nil, fmt.Errorf("packet too small")
	}

	nonce := packet[1:1 + chacha20poly1305.NonceSize]
	ciphertext := packet[1 + chacha20poly1305.NonceSize:]

	if !peer.filter.ValidateNonce(binary.BigEndian.Uint64(nonce)) {
		return nil, fmt.Errorf("invalid nonce")
	}

	cipher, err := chacha20poly1305.New(peer.c2sKey)
	if err != nil {
		return nil, fmt.Errorf("failed to init cipher: %w", err)
	}

	plaintext, err := cipher.Open(nil, nonce, ciphertext, packet[:13])
	if err != nil {
		return nil, fmt.Errorf("failed decrypting: %w", err)
	}

	return plaintext, nil
}
