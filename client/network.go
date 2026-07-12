package client

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"log"
	"time"

	"github.com/lbodlev888/ownvpn/crypto"
	"github.com/lbodlev888/ownvpn/proto"
	"golang.org/x/crypto/chacha20poly1305"
)

func keepaliveLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-time.After(25 * time.Second):
		}

		//even if here we do not encrypt we dont need to send keepalives if session isnt initialized
		if c2sKey.Load() == nil || s2cKey.Load() == nil {
			continue
		}

		keepaliveBytes := proto.EncodeKeepAlive(proto.MsgKeepAliveSYN)
		_, err := conn.WriteTo(keepaliveBytes, serverAddr)
		if err != nil {
			log.Println("Failed to send keepalive: " + err.Error())
		}
	}
}

func udpReadLoop(ctx context.Context) {
	buf := make([]byte, buffersize)
	for {
		if ctx.Err() != nil {
			return
		}

		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Failed to read from server: " + err.Error())
			continue
		}

		if n < 1 || src.String() != serverAddr.String() {
			continue
		}

		if buf[0] == proto.MsgServerHello {
			select {
			case serverHelloChan <- append([]byte(nil), buf[:n]...):
			default:
			}
			continue
		}

		if s2cKey.Load() == nil {
			continue
		}

		if buf[0] != proto.MsgData {
			continue
		}

		payload := buf[1:n]
		if len(payload) < chacha20poly1305.NonceSize {
			continue
		}

		nonce := payload[:chacha20poly1305.NonceSize]
		ciphertext := payload[chacha20poly1305.NonceSize:]

		k := s2cKey.Load()
		if k == nil {
			continue
		}

		aead, err := chacha20poly1305.New(k[:])
		if err != nil {
			log.Println("Failed to init aead cipher: " + err.Error())
			continue
		}

		frame, err := aead.Open(nil, nonce, ciphertext, nil)
		if err != nil {
			log.Println("Invalid encrypted frame: " + err.Error())
			continue
		}

		currentNonceIn := binary.BigEndian.Uint64(nonce)
		if !filter.ValidateNonce(currentNonceIn) {
			continue
		}

		iface.Write(frame)
	}
}

func tunReadLoop(ctx context.Context) {
	packet := make([]byte, buffersize)
	for {
		if ctx.Err() != nil {
			return
		}

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

		k := c2sKey.Load()
		if k == nil {
			continue
		}

		aead, err := chacha20poly1305.New(k[:])
		if err != nil {
			log.Println("Failed to init aead cipher: " + err.Error())
			continue
		}

		nonce := make([]byte, chacha20poly1305.NonceSize)
		n := lastNonceOut.Add(1)
		binary.BigEndian.PutUint64(nonce, n)

		out := make([]byte, 0, 1+len(nonce)+plen+chacha20poly1305.Overhead)
		out = append(out, proto.MsgData)
		out = append(out, nonce...)

		out = aead.Seal(out, nonce, packet[:plen], nil)

		if _, err := conn.WriteTo(out, serverAddr); err != nil {
			log.Println("Failed to write packet: " + err.Error())
			s2cKey.Store(nil)
			c2sKey.Store(nil)
			cipherChan <- struct{}{}
			continue
		}
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

		ephemeralPrivKey, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			log.Println("Failed to generate ephemeral private key: " + err.Error())
			continue
		}

		clientHello := proto.ClientHello{
			Name: cfg.Name,
			PublicKey: ephemeralPrivKey.PublicKey().Bytes(),
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
		case <- serverHelloChan:
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
		case respBuf = <- serverHelloChan:
		case <-time.After(2 * time.Second):
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

		remotePublic, err := ecdh.P256().NewPublicKey(serverHello.PublicKey)
		if err != nil {
			log.Println("Failed to parse remote ephemeral public key: " + err.Error())
			return
		}

		sharedSecret, err := ephemeralPrivKey.ECDH(remotePublic)

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

		confirmNonce := make([]byte, chacha20poly1305.NonceSize)
		binary.BigEndian.PutUint64(confirmNonce, lastNonceOut.Add(1))
		if aead, err := chacha20poly1305.New(k1[:]); err == nil {
			confirm := append([]byte{proto.MsgClientConfirm}, confirmNonce...)
			confirm = aead.Seal(confirm, confirmNonce, nil, nil)
			conn.WriteTo(confirm, serverAddr)
		}

		log.Println("Latest handshake " + time.Now().Format(time.RFC1123))

		select {
		case <-ctx.Done():
			return
		case <-time.After(handshake_timeout): //re-establish encrypted connection
		case <-cipherChan:
		}
	}
}
