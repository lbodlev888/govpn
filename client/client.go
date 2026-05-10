package client

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

	"github.com/lbodlev888/ownvpn/config"
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

	raw_decaps, err := base64.StdEncoding.DecodeString(cfg.DecapsKey)
	if err != nil { log.Fatalln("Could not decode private key: " + err.Error()) }

	raw_encaps, err := base64.StdEncoding.DecodeString(cfg.EncapsKey)
	if err != nil { log.Fatalln("Could not decode public key: " + err.Error()) }

	decaps, err := mlkem.NewDecapsulationKey768(raw_decaps)
	if err != nil { log.Fatalln("Could not import private key: " + err.Error()) }

	encaps, err := mlkem.NewEncapsulationKey768(raw_encaps)
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

	log.Println("This is config name: " + cfg.Name)
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

	encryptionKey, err := hkdf.Key(sha256.New, final_key, nil, "own_vpn0.0.1", chacha20poly1305.KeySize)
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

	go func(){
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			enc_frame, err := network.ReadFrame(conn)
			if err != nil {
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
	}()

	packet := make([]byte, BUFFERSIZE)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		plen, err := iface.Read(packet)
		if err != nil {
			log.Println("Failed to read: " + err.Error())
			cancel()
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
}
