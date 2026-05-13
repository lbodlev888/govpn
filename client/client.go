package client

import (
	"context"
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/lbodlev888/ownvpn/config"
	"github.com/lbodlev888/ownvpn/crypto"
	"github.com/lbodlev888/ownvpn/proto"
	"github.com/lbodlev888/ownvpn/tunif"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	BUFFERSIZE = 2048
)

func RunClient(ctx context.Context, cfg *config.PeerConfig, cancel context.CancelFunc) {
	if cfg.Endpoint == "" {
		log.Fatalln("Missing endpoint. Cant connect to nobody")
		return
	}

	iface, err := tunif.SetupInterface(fmt.Sprintf("%s/%d", cfg.VirtualIP, cfg.Subnet))
	if err != nil {
		log.Fatalln("Could not create tun interface: " + err.Error())
	}

	decaps, err := crypto.ParseDecapsKey(cfg.DecapsKey)
	if err != nil {
		log.Fatalln("Could not import private key: " + err.Error())
	}

	encaps, err := crypto.ParseEncapsKey(cfg.EncapsKey)
	if err != nil {
		log.Fatalln("Could not import public key: " + err.Error())
	}

	sharedKey1, ciphertext := encaps.Encapsulate()

	serverAddr, err := net.ResolveUDPAddr("udp", cfg.Endpoint)
	if err != nil {
		log.Fatalln("Could not resolve endpoint: " + err.Error())
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Println("Failed to connect to server: " + err.Error())
		return
	}
	defer conn.Close()

	log.Println("Peer name: " + cfg.Name)

	clientHelloBytes, err := proto.EncodeClientHello(proto.ClientHello{
		Name:       cfg.Name,
		PublicData: ciphertext,
	})
	if err != nil {
		log.Fatalln("Failed to encode ClientHello: " + err.Error())
	}

	if _, err := conn.Write(clientHelloBytes); err != nil {
		log.Fatalln("Failed to send ClientHello: " + err.Error())
	}

	respBuf := make([]byte, BUFFERSIZE)
	n, err := conn.Read(respBuf)
	if err != nil {
		log.Fatalln("Failed to read ServerHello: " + err.Error())
	}

	serverHello, err := proto.DecodeServerHello(respBuf[:n])
	if err != nil {
		log.Fatalln("Invalid ServerHello: " + err.Error())
	}

	sharedKey2, err := decaps.Decapsulate(serverHello.PublicData)
	if err != nil {
		log.Fatalln("Could not decapsulate ServerHello: " + err.Error())
	}

	final_key := append(sharedKey1, sharedKey2...)

	infoString, ok := ctx.Value("version").(string)
	if !ok {
		log.Fatalln("Missing ownvpn version key in context")
	}

	encryptionKey, err := crypto.DeriveEncryptionKey(final_key, nil, infoString, chacha20poly1305.KeySize)
	if err != nil {
		log.Println("Could not derive encryption key: " + err.Error())
		return
	}

	log.Println("Connection established")

	cipher, err := chacha20poly1305.New(encryptionKey)
	if err != nil {
		log.Println("Could not init symmetric cipher: " + err.Error())
		return
	}

	var wg sync.WaitGroup

	wg.Go(func() {
		<-ctx.Done()
		log.Println("Received stop signal. Closing everything")
		conn.Close()
		iface.Close()
	})

	wg.Go(func() {
		buf := make([]byte, BUFFERSIZE)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				log.Println("Failed to read from server: " + err.Error())
				return
			}
			if n < 1 || buf[0] != proto.MsgData {
				continue
			}
			payload := buf[1:n]
			if len(payload) < chacha20poly1305.NonceSize {
				continue
			}
			nonce := payload[:chacha20poly1305.NonceSize]
			ciphertext := payload[chacha20poly1305.NonceSize:]

			frame, err := cipher.Open(nil, nonce, ciphertext, nil)
			if err != nil {
				log.Println("Invalid encrypted frame: " + err.Error())
				continue
			}

			iface.Write(frame)
		}
	})

	packet := make([]byte, BUFFERSIZE)
	for {
		plen, err := iface.Read(packet)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			log.Println("Failed to read from iface: " + err.Error())
			break
		}

		nonce := make([]byte, chacha20poly1305.NonceSize)
		rand.Read(nonce)

		out := make([]byte, 0, 1+len(nonce)+plen+chacha20poly1305.Overhead)
		out = append(out, proto.MsgData)
		out = append(out, nonce...)
		out = cipher.Seal(out, nonce, packet[:plen], nil)

		if _, err := conn.Write(out); err != nil {
			log.Println("Failed to write packet: " + err.Error())
			cancel()
			break
		}
	}

	wg.Wait()
}
