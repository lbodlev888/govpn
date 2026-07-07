package client

import (
	"context"
	"crypto/mlkem"
	"encoding/binary"
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
	buffersize = 2048
	handshake_timeout = 5 * time.Minute
)

var (
	iface *water.Interface
	s2cKey, c2sKey atomic.Pointer[[chacha20poly1305.KeySize]byte]
	lastNonceIn, lastNonceOut atomic.Uint64
	cipherChan chan struct{}
	serverAddr *net.UDPAddr
	conn *net.UDPConn
	cfg *config.PeerConfig
	decaps *mlkem.DecapsulationKey768
	encaps *mlkem.EncapsulationKey768
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
		if s2cKey.Load() == nil {
			<-time.After(100 * time.Millisecond)
			continue
		}

		n, src, err := conn.ReadFrom(buf)
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			log.Println("Failed to read from server: " + err.Error())
			continue
		}

		if s2cKey.Load() == nil || n < 1 || src.String() != serverAddr.String() {
			continue
		}

		if buf[0] == proto.MsgKeepAlive {
			keepaliveStatus := proto.DecodeKeepAlive(buf[:n], proto.MsgKeepAliveACK)
			log.Printf("Received keepalive. Status: %t\n", keepaliveStatus)
			if !keepaliveStatus {
				c2sKey.Store(nil)
				s2cKey.Store(nil)
				cipherChan <- struct{}{}
			}
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

		currentNonceIn := binary.BigEndian.Uint64(nonce)
		if currentNonceIn <= lastNonceIn.Load() {
			log.Println("Possible replay attack. Dropping packet")
			continue
		}

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
			s2cKey.Store(nil)
			c2sKey.Store(nil)
			cipherChan <- struct{}{}
			continue
		}
		lastNonceIn.Store(currentNonceIn)

		iface.Write(frame)
	}
}

func tunReadLoop(ctx context.Context) {
	packet := make([]byte, buffersize)
	for {
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

		if c2sKey.Load() == nil {
			continue
		}

		nonce := make([]byte, chacha20poly1305.NonceSize)
		n := lastNonceOut.Add(1)
		binary.BigEndian.PutUint64(nonce, n)

		out := make([]byte, 0, 1 + len(nonce) + plen + chacha20poly1305.Overhead)
		out = append(out, proto.MsgData)
		out = append(out, nonce...)

		k := c2sKey.Load()
		if k == nil {
			continue
		}

		aead, err := chacha20poly1305.New(k[:])
		if err != nil {
			log.Println("Failed to init aead cipher: " + err.Error())
			continue
		}

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
		lastNonceIn.Store(0) 
		lastNonceOut.Store(0)

		log.Println("Re-handshaking...")

		sharedKey1, ciphertext := encaps.Encapsulate()

		clientHelloBytes, err := proto.EncodeClientHello(proto.ClientHello{
			Name:       cfg.Name,
			PublicData: ciphertext,
		})
		if err != nil {
			log.Println("Failed to encode ClientHello: " + err.Error())
			continue
		}
	
		if _, err := conn.WriteTo(clientHelloBytes, serverAddr); err != nil {
			log.Println("Failed to send ClientHello: " + err.Error())
			<-time.After(5 * time.Second)
			continue
		}
	
		respBuf := make([]byte, buffersize)
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, src, err := conn.ReadFrom(respBuf)
		if err != nil {
			log.Println("Failed to read ServerHello: " + err.Error())
			continue
		}
		conn.SetReadDeadline(time.Time{})
		if src.String() != serverAddr.String() {
			continue
		}
	
		serverHello, err := proto.DecodeServerHello(respBuf[:n])
		if err != nil {
			log.Println("Invalid ServerHello: " + err.Error())
			continue
		}
	
		sharedKey2, err := decaps.Decapsulate(serverHello.PublicData)
		if err != nil {
			log.Println("Could not decapsulate ServerHello: " + err.Error())
			continue
		}
	
		final_key := append(sharedKey1, sharedKey2...)
	
		c2s, err := crypto.DeriveEncryptionKey(final_key, nil, "c2s", chacha20poly1305.KeySize)
		if err != nil {
			log.Println("Could not derive encryption key: " + err.Error())
			continue
		}
		var k1 [chacha20poly1305.KeySize]byte
		copy(k1[:], c2s)
		c2sKey.Store(&k1)

		s2c, err := crypto.DeriveEncryptionKey(final_key, nil, "s2c", chacha20poly1305.KeySize)
		if err != nil {
			log.Println("Could not derive encryption key: " + err.Error())
			continue
		}
		var k2 [chacha20poly1305.KeySize]byte
		copy(k2[:], s2c)
		s2cKey.Store(&k2)
	
		log.Println("Latest handshake " + time.Now().Format(time.RFC1123))
		
		select {
		case <-ctx.Done():
			return
		case <-time.After(handshake_timeout): //re-establish encrypted connection
		case <-cipherChan:
		}
	}
}
