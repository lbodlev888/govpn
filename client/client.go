package client

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/lbodlev888/ownvpn/config"
	"github.com/lbodlev888/ownvpn/crypto"
	"github.com/lbodlev888/ownvpn/proto"
	"github.com/lbodlev888/ownvpn/tunif"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	BUFFERSIZE = 2048
	HANDSHAKE_TIMEOUT = 5 * time.Minute
)

func RunClient(ctx context.Context, cfg *config.PeerConfig) {
	var aead cipher.AEAD
	cipherChan := make(chan struct{})
	encryptionKey := make([]byte, chacha20poly1305.KeySize)

	if cfg.Endpoint == "" {
		log.Println("Missing endpoint. Cant connect to nobody")
		return
	}

	iface, err := tunif.SetupInterface(fmt.Sprintf("%s/%d", cfg.VirtualIP, cfg.Subnet))
	if err != nil {
		log.Println("Could not create tun interface: " + err.Error())
		return
	}

	if cfg.FullTunnel {
		defer func() {
			if err := tunif.ClearFullTunnel(strings.Split(cfg.Endpoint, ":")[0]); err != nil {
				log.Println(err)
			}
		}()
		err := tunif.SetupFullTunnel(strings.Split(cfg.Endpoint, ":")[0])
		if err != nil {
			log.Println("Failed to setup full tunnel")
			return
		}
	}

	decaps, err := crypto.ParseDecapsKey(cfg.DecapsKey)
	if err != nil {
		log.Println("Could not import private key: " + err.Error())
		return
	}

	encaps, err := crypto.ParseEncapsKey(cfg.EncapsKey)
	if err != nil {
		log.Println("Could not import public key: " + err.Error())
		return
	}

	serverAddr, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
	if err != nil {
		log.Println("Could not resolve endpoint: " + err.Error())
		return
	}

	lAddr, _ := net.ResolveUDPAddr("udp", "0.0.0.0:0")
	conn, err := net.ListenUDP("udp", lAddr)
	if err != nil {
		log.Println("Failed to connect to server: " + err.Error())
		return
	}
	defer conn.Close()

	log.Println("Peer name: " + cfg.Name)

	var wg sync.WaitGroup

	wg.Go(func() {
		for {
			if ctx.Err() != nil {
				log.Println("Handshake process stopped")
				return
			}

			aead = nil
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
		
			respBuf := make([]byte, BUFFERSIZE)
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
		
			infoString, ok := ctx.Value("version").(string)
			if !ok {
				log.Fatalln("Missing ownvpn version key in context")
			}
		
			encryptionKey, err = crypto.DeriveEncryptionKey(final_key, nil, infoString, chacha20poly1305.KeySize)
			if err != nil {
				log.Println("Could not derive encryption key: " + err.Error())
				continue
			}
		
			log.Println("Latest handshake " + time.Now().Format(time.RFC1123))
			aead, err = chacha20poly1305.New(encryptionKey)
			if err != nil {
				log.Println("Failed to init cipher: " + err.Error())
				continue
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(HANDSHAKE_TIMEOUT): //re-establish encrypted connection
			case <-cipherChan:
			}
		}
	})

	wg.Go(func() {
		<-ctx.Done()
		log.Println("Received stop signal. Closing everything")
		conn.Close()
		iface.Close()
	})

	//keepalive process
	wg.Go(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(25 * time.Second):
			}

			//even if here we do not encrypt we dont need to send keepalives if session isnt initiated
			if aead == nil {
				continue
			}

			keepaliveBytes := proto.EncodeKeepAlive(proto.MsgKeepAliveSYN)
			_, err := conn.WriteTo(keepaliveBytes, serverAddr)
			if err != nil {
				log.Println("Failed to send keepalive: " + err.Error())
			}
		}
	})

	wg.Go(func() {
		buf := make([]byte, BUFFERSIZE)
		for {
			if ctx.Err() != nil {
				break
			} else if aead == nil {
				<-time.After(100 * time.Millisecond)
				continue
			}

			n, src, err := conn.ReadFrom(buf)
			if err != nil {
				log.Println("Failed to read from server: " + err.Error())
				continue
			}

			if aead == nil || n < 1 || src.String() != serverAddr.String() {
				continue
			}

			if buf[0] == proto.MsgKeepAlive {
				keepaliveStatus := proto.DecodeKeepAlive(buf[:n], proto.MsgKeepAliveACK)
				log.Printf("Received keepalive. Status: %t\n", keepaliveStatus)
				if !keepaliveStatus {
					aead = nil
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

			frame, err := aead.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				log.Println("Invalid encrypted frame: " + err.Error())
				aead = nil
				cipherChan <- struct{}{}
				continue
			}

			iface.Write(frame)
		}
	})

	packet := make([]byte, BUFFERSIZE)
	for {
		if ctx.Err() != nil {
			break
		} else if aead == nil {
			<-time.After(100 * time.Millisecond)
			continue
		}

		plen, err := iface.Read(packet)
		if err != nil {
			log.Println("Failed to read from iface: " + err.Error())
			continue
		}

		if aead == nil {
			continue
		}

		nonce := make([]byte, chacha20poly1305.NonceSize)
		rand.Read(nonce)

		out := make([]byte, 0, 1 + len(nonce) + plen + chacha20poly1305.Overhead)
		out = append(out, proto.MsgData)
		out = append(out, nonce...)

		out = aead.Seal(out, nonce, packet[:plen], nil)

		if _, err := conn.WriteTo(out, serverAddr); err != nil {
			log.Println("Failed to write packet: " + err.Error())
			aead = nil
			cipherChan <- struct{}{}
			continue
		}
	}

	wg.Wait()
}
