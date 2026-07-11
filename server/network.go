package server

import (
	"context"
	"crypto/mlkem"
	"encoding/binary"
	"log"
	"net"
	"time"

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
			handleHandshake(pkt, src)
		case proto.MsgData:
			handleData(pkt[1:], src)
		case proto.MsgKeepAlive:
			log.Println("Received keepalive from " + src.String())
		case proto.MsgClientConfirm:
			handleConfirm(pkt, src)
		default:
			log.Printf("Invalid packet from %s\n", net.IP(src.IP).String())
		}
	}
}

func handleConfirm(pkt []byte, src *net.UDPAddr) {
	pendingMu.Lock()
	pend, ok := pendingByAddr[src.String()]
	pendingMu.Unlock()
	if !ok {
		return
	}

	payload := pkt[1:]
	if len(payload) < chacha20poly1305.NonceSize {
		return
	}

	aead, err := chacha20poly1305.New(pend.peer.c2sKey)
	if err != nil {
		log.Println("Failed to init cipher: " + err.Error())
		return
	}

	nonce := payload[:chacha20poly1305.NonceSize]
	ciphertext := payload[chacha20poly1305.NonceSize:]

	if _, err := aead.Open(nil, nonce, ciphertext, nil); err != nil {
		return
	}
	if !pend.peer.filter.ValidateNonce(binary.BigEndian.Uint64(nonce)) {
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

/*func sendAckKeepAlive(pkt []byte, src *net.UDPAddr) {
	if proto.DecodeKeepAlive(pkt, proto.MsgKeepAliveSYN) {
		if _, err := udpConn.WriteToUDP(proto.EncodeKeepAlive(proto.MsgKeepAliveACK), src); err != nil {
			log.Println("Failed to send keepalive syn:" + err.Error())
		}
		return
	}
	log.Println("Received invalid keepalive from: " + src.String())
}*/

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
		peer: newPeer,
		name: peerCfg.Name,
		virtualIP: peerCfg.VirtualIP,
		createdAt: time.Now(),
	}
	pendingMu.Unlock()
}

func handleData(payload []byte, src *net.UDPAddr) {
	peersMu.RLock()
	peer, ok := peersByAddr[src.String()]
	peersMu.RUnlock()
	if !ok || peer.disabled {
		return
	}

	if len(payload) < chacha20poly1305.NonceSize {
		return
	}

	aead, err := chacha20poly1305.New(peer.c2sKey)
	if err != nil {
		log.Println("Failed to init cipher: " + err.Error())
		return
	}

	nonce := payload[:chacha20poly1305.NonceSize]
	ciphertext := payload[chacha20poly1305.NonceSize:]

	frame, err := aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		log.Printf("Failed to decrypt frame from %s: %v\n", src.String(), err.Error())
		return
	}

	currentNonceIn := binary.BigEndian.Uint64(nonce)
	if !peer.filter.ValidateNonce(currentNonceIn) {
		return
	}

	if len(frame) < 20 || frame[0]>>4 != 4 {
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

		if len(actualData) < 20 || actualData[0]>>4 != 4 {
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
	cipher, err := chacha20poly1305.New(peer.s2cKey)
	if err != nil {
		log.Println("Failed to init cipher: " + err.Error())
		return
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	n := peer.lastNonceOut.Add(1)
	binary.BigEndian.PutUint64(nonce, n)

	out := make([]byte, 0, 1+len(nonce)+len(frame)+chacha20poly1305.Overhead)
	out = append(out, proto.MsgData)
	out = append(out, nonce...)
	out = cipher.Seal(out, nonce, frame, nil)

	if _, err := udpConn.WriteToUDP(out, peer.Addr); err != nil {
		log.Println("Failed to send to peer " + peer.Addr.String() + ": " + err.Error())
	}
}
