package client

import (
	"context"
	"crypto/mlkem"
	"encoding/binary"
	"fmt"
	"log"
	"time"

	"github.com/lbodlev888/govpn/crypto"
	"github.com/lbodlev888/govpn/proto"
	"golang.org/x/crypto/chacha20poly1305"
)

func keepaliveLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(keepaliveTimeout):
		}

		//do not send keepalives if the session isnt initialized
		if c2sKey.Load() == nil || s2cKey.Load() == nil {
			continue
		}

		select {
		case <-keepAliveChan:
		default:
		}

		sendEncrypted(proto.MsgKeepAliveSYN, nil)

		var keepaliveAck []byte
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
			c2sKey.Store(nil)
			s2cKey.Store(nil)
			cipherChan <- struct{}{}
			continue
		case keepaliveAck = <- keepAliveChan:
		}

		if _, err := parseEncrypted(proto.MsgKeepAliveACK, keepaliveAck); err != nil {
			c2sKey.Store(nil)
			s2cKey.Store(nil)
			cipherChan <- struct{}{}
			log.Println("invalid keepaliveAck")
		}
	}
}

func udpReadLoop(ctx context.Context) {
	buf := make([]byte, buffersize)
	for {
		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Failed to read from server: " + err.Error())
			continue
		}

		if src.String() != serverAddr.String() {
			continue
		}

		switch buf[0] {
		case proto.MsgServerHello:
			serverHelloChan <- append([]byte(nil), buf[:n]...)
			continue
		case proto.MsgKeepAliveACK:
			keepAliveChan <- append([]byte(nil), buf[:n]...)
			continue
		}

		if s2cKey.Load() == nil {
			continue
		}

		frame, err := parseEncrypted(proto.MsgData, buf[:n])
		if err != nil {
			log.Println("Failed parsing encrypted packet: " + err.Error())
			continue
		}

		_, _ = iface.Write(frame)
	}
}

func tunReadLoop(ctx context.Context) {
	packet := make([]byte, buffersize)
	for {
		if ctx.Err() != nil {
			return
		}

		//ignore all packets until a valid session gets established
		if c2sKey.Load() == nil {
			<-time.After(100 * time.Millisecond)
			continue
		}

		plen, err := iface.Read(packet)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Failed to read from iface: " + err.Error())
			continue
		}

		sendEncrypted(proto.MsgData, append([]byte(nil), packet[:plen]...))
	}
}

func rehandshakeLoop(ctx context.Context) {
	for {
		if ctx.Err() != nil {
			return
		}

		s2cKey.Store(nil)
		c2sKey.Store(nil)
		filter.Reset()
		lastNonceOut.Store(0)

		log.Println("Re-handshaking...")

		ephemeralMLKEM, err := mlkem.GenerateKey768()
		if err != nil {
			log.Println("Failed to generate ephemeral keypair: " + err.Error())
			continue
		}

		clientHello := proto.ClientHello{
			Name:      cfg.Name,
			EncapsKey: ephemeralMLKEM.EncapsulationKey().Bytes(),
		}

		if err := crypto.SignClientHello(privKey, &clientHello); err != nil {
			log.Println("Failed to sign client hello: " + err.Error())
			continue
		}

		clientHelloBytes, err := proto.EncodeClientHello(clientHello)
		if err != nil {
			log.Println("Failed to encode ClientHello: " + err.Error())
			continue
		}

		select {
		case <-serverHelloChan:
		default:
		}

		if _, err := conn.WriteTo(clientHelloBytes, serverAddr); err != nil {
			log.Println("Failed to send ClientHello: " + err.Error())
			<-time.After(5 * time.Second)
			continue
		}

		var respBuf []byte
		select {
		case <-ctx.Done():
			return
		case respBuf = <-serverHelloChan:
		case <-time.After(2 * time.Second):
			log.Println("ServerHello timeout")
			continue
		}

		serverHello, err := proto.DecodeServerHello(respBuf)
		if err != nil {
			log.Println("Invalid ServerHello: " + err.Error())
			continue
		}

		if !crypto.CheckServerHello(pubKey, serverHello) {
			log.Println("Invalid signature from server")
			continue
		}

		sharedSecret, err := ephemeralMLKEM.Decapsulate(serverHello.Ciphertext)
		if err != nil {
			log.Println("Could not decapsulate ServerHello: " + err.Error())
			continue
		}

		c2s, err := crypto.DeriveEncryptionKey(sharedSecret, nil, "c2s_" + cfg.Name, chacha20poly1305.KeySize)
		if err != nil {
			log.Println("Could not derive encryption key: " + err.Error())
			continue
		}
		var k1 [chacha20poly1305.KeySize]byte
		copy(k1[:], c2s)
		c2sKey.Store(&k1)

		s2c, err := crypto.DeriveEncryptionKey(sharedSecret, nil, "s2c_" + cfg.Name, chacha20poly1305.KeySize)
		if err != nil {
			log.Println("Could not derive encryption key: " + err.Error())
			continue
		}
		var k2 [chacha20poly1305.KeySize]byte
		copy(k2[:], s2c)
		s2cKey.Store(&k2)

		sendEncrypted(proto.MsgClientConfirm, nil)
		log.Println("Latest handshake " + time.Now().Format(time.RFC1123))

		select {
		case <-ctx.Done():
			return
		case <-time.After(handshakeTimeout): //re-establish encrypted connection
		case <-cipherChan:
		}
	}
}

func sendEncrypted(messageType byte, packet []byte) {
	key := c2sKey.Load()
	if key == nil {
		return
	}

	cipher, err := chacha20poly1305.New(key[:])
	if err != nil {
		log.Println("Failed to init cipher: " + err.Error())
		return
	}

	nonce := make([]byte, chacha20poly1305.NonceSize)
	binary.BigEndian.PutUint64(nonce, lastNonceOut.Add(1))

	out := make([]byte, 1, 1+chacha20poly1305.NonceSize+len(packet)+chacha20poly1305.Overhead)
	out[0] = messageType
	out = append(out, nonce...)
	out = cipher.Seal(out, nonce, packet, out[:13])

	if _, err := conn.WriteToUDP(out, serverAddr); err != nil {
		log.Println("Failed to send to server: " + err.Error())
	}
}

func parseEncrypted(expectedFlag byte, packet []byte) ([]byte, error) {
	if len(packet) < chacha20poly1305.NonceSize || packet[0] != expectedFlag {
		return nil, fmt.Errorf("invalid packet: too small or header mismatch")
	}

	s2c := s2cKey.Load()
	if s2c == nil {
		return nil, fmt.Errorf("session not initialized")
	}

	nonce := packet[1:1+chacha20poly1305.NonceSize]
	ciphertext := packet[1+chacha20poly1305.NonceSize:]

	if !filter.ValidateNonce(binary.BigEndian.Uint64(nonce)) {
		return nil, fmt.Errorf("invalid nonce")
	}

	cipher, err := chacha20poly1305.New(s2c[:])
	if err != nil {
		return nil, fmt.Errorf("failed to init cipher: %w", err)
	}

	plaintext, err := cipher.Open(nil, nonce, ciphertext, packet[:13])
	if err != nil {
		return nil, fmt.Errorf("failed decrypting: %w", err)
	}

	return plaintext, nil
}
