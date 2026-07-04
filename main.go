package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/lbodlev888/ownvpn/client"
	"github.com/lbodlev888/ownvpn/config"
	"github.com/lbodlev888/ownvpn/crypto"
	"github.com/lbodlev888/ownvpn/server"
)

const OWNVPN_VERSION = "ownvpn0.0.4"

func main() {
	serverMode := flag.Bool("server", false, "Run in server mode") //in future move to bare or web mode
	generateKey := flag.Bool("genkey", false, "Generate cryptographic keys")
	pubKey := flag.String("pubkey", "", "Get public key from private key")
	configFile := flag.String("config", "/etc/ownvpn/config.json", "Provide the path to configuration file")

	flag.Parse()

	if *generateKey {
		priv, err := crypto.GeneratePrivate()
		if err != nil {
			log.Println(err)
			return
		}
		fmt.Println("Private key: " + priv)
		return
	}

	if *pubKey != "" {
		pubkey, err := crypto.GetPublicKey(*pubKey)
		if err != nil {
			log.Println(err)
			return
		}
		fmt.Println("Public key: " + pubkey)
		return
	}

	if *configFile == "" {
		flag.Usage()
		log.Fatalln("Missing configuration file")
	}

	//move version key to org
	ctx, _ := signal.NotifyContext(context.WithValue(context.Background(), "version", OWNVPN_VERSION), os.Interrupt)

	rawConfig, err := os.ReadFile(*configFile)
	if err != nil {
		log.Println("Failed to read configuration file: " + err.Error())
		return
	}

	if *serverMode {
		var cfg config.ServerConfig
		if err := json.Unmarshal(rawConfig, &cfg); err != nil {
			log.Println("Failed to parse configuration: " + err.Error())
			return
		}

		if err := server.Init(cfg); err != nil {
			log.Println("failed to init: " + err.Error())
			return
		}
		server.Run(ctx)
	} else {
		var cfg config.PeerConfig
		if err := json.Unmarshal(rawConfig, &cfg); err != nil {
			log.Println("Failed to parse configuration: " + err.Error())
			return
		}

		client.Run(ctx, cfg)
	}
}
