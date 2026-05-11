package client

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"sync"

	"github.com/lbodlev888/ownvpn/config"
	"github.com/lbodlev888/ownvpn/crypto"
	"github.com/lbodlev888/ownvpn/network"
	"github.com/lbodlev888/ownvpn/proto"
	"github.com/lbodlev888/ownvpn/tunif"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	BUFFERSIZE = 1500
)

func RunClient(ctx context.Context, cfg *config.PeerConfig, cancel context.CancelFunc) {
	if cfg.Endpoint == "" {
		log.Fatalln("Missing endpoint. Cant connect to nobody")
		return
	}

	iface, err := tunif.SetupInterface(fmt.Sprintf("%s/%d", cfg.VirtualIP, cfg.Subnet))
	if err != nil { log.Fatalln("Could not create tun interface: " + err.Error()) }

	decaps, err := crypto.ParseDecapsKey(cfg.DecapsKey)
	if err != nil { log.Fatalln("Could not import private key: " + err.Error()) }

	encaps, err := crypto.ParseEncapsKey(cfg.EncapsKey)
	if err != nil { log.Fatalln("Could not import public key: " + err.Error()) }

	sharedKey1, ciphertext := encaps.Encapsulate()

	conn, err := net.Dial("tcp", cfg.Endpoint)
	if err != nil {
		log.Println("Failed to connect to server: " + err.Error())
		return
	}
	defer conn.Close()

	enc := json.NewEncoder(conn)
	dec := json.NewDecoder(conn)

	log.Println("Peer name: " + cfg.Name)
	if err := enc.Encode(proto.ClientHello{
		PublicData: ciphertext,
		Name: cfg.Name,
	}); err != nil {
		log.Fatalln("Failed to send clientHello: " + err.Error())
		return
	}

	var serverHello proto.ServerHello
	if err := dec.Decode(&serverHello); err != nil {
		log.Fatalln("Failed to decode serverHello: " + err.Error())
		return
	}

	sharedKey2, err := decaps.Decapsulate(serverHello.PublicData)
	if err != nil {
		log.Fatalln("Could not decrypt public data from serverHello: " + err.Error())
	}

	final_key := append(sharedKey1, sharedKey2...)

	infoString, ok := ctx.Value("version").(string)
	if !ok {
		log.Fatalln("Missing ownvpn version key in context")
	}

	encryptionKey, err := crypto.DeriveEncryptionKey(final_key, nil, infoString, chacha20poly1305.KeySize)
	if err != nil {
		log.Println("Coult not derive encryption key: " + err.Error())
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
		log.Println("Received stop signal. Clossing everything")
		conn.Close()
		iface.Close()
	})

	wg.Go(func(){
		for {
			enc_frame, err := network.ReadFrame(conn)
			if err != nil {
				if ctx.Err() != nil { return }

				log.Println("Failed to read: " + err.Error())
				return
			}

			nonce := enc_frame[:chacha20poly1305.NonceSize]
			enc_frame = enc_frame[chacha20poly1305.NonceSize:]

			frame, err := cipher.Open(nil, nonce, enc_frame, nil)
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
			if ctx.Err() != nil { break }

			log.Println("Failed to read: " + err.Error())
			break
		}

		nonce := make([]byte, chacha20poly1305.NonceSize)
		rand.Read(nonce)
		enc_data := cipher.Seal(nil, nonce, packet[:plen], nil)
		final_packet := append(nonce, enc_data...)

		if err := network.WriteFrame(conn, final_packet); err != nil {
			log.Println("Failed to write packet: " + err.Error())
			cancel()
			break
		}
	}

	wg.Wait()
}
