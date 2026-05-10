package main

import (
	"context"
	"encoding/json"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"vpn/client"
	"vpn/config"
	"vpn/crypto"
	"vpn/server"
)

func main() {
	serverMode := flag.Bool("server", false, "Run in server mode")
	generateKeys := flag.Bool("genkey", false, "Run to generate cryptographic keys")
	configFile := flag.String("config", "", "Provide configuration file")

	flag.Parse()

	if *generateKeys {
		crypto.GenerateCrypto()
		return
	}

	if *configFile == "" {
		flag.Usage()
		log.Fatalln("Missing configuration file")
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	file, err := os.Open(*configFile)
	if err != nil {
		log.Fatalln("Could not open config file: " + err.Error())
	}
	dec := json.NewDecoder(file)

	if *serverMode {
		var cfg config.ServerConfig
		if err := dec.Decode(&cfg); err != nil {
			log.Fatalln("Could not parse server configuration file: " + err.Error())
		}

		server.RunServer(ctx, &cfg, cancel)
	} else {
		var cfg config.PeerConfig
		if err := dec.Decode(&cfg); err != nil {
			log.Fatalln("Could not parse peer configuration file: " + err.Error())
		}

		client.RunClient(ctx, &cfg, cancel)
	}
}
