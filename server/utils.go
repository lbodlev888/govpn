package server

import (
	"context"
	"log"
	"net"
	"os"
	"strings"
)

func loadAllowedPeers() {
	allowedPeersMu.Lock()
	defer allowedPeersMu.Unlock()

	clear(allowedPeers)

	for _, p := range cfg.Peers {
		allowedPeers[p.Name] = p
	}
}

func listenForSignals(ctx context.Context) {
	os.Remove("/tmp/ownvpn.sock")
	unixListener, err := net.Listen("unix", "/tmp/ownvpn.sock")
	if err != nil {
		log.Println("failed to aquire listener: " + err.Error())
		return
	}
	defer unixListener.Close()

	wg.Go(func() {
		<-ctx.Done()
		unixListener.Close()
	})

	for {
		client, err := unixListener.Accept()
		if err != nil {
			log.Println("Failed to accept client: " + err.Error())
			continue
		}

		wg.Go(func() {
			handleUnixClient(client)
		})
	}
}

func handleUnixClient(client net.Conn) {
	client.Write([]byte("Input command: "))
	buf := make([]byte, 1024)
	n, err := client.Read(buf)
	if err != nil {
		log.Println("Failed to read command from unix client: " + err.Error())
		return
	}

	input := strings.TrimSpace(string(buf[:n]))
	command := strings.Split(input, ":")
	switch command[0] {
	case "enable":
		EnablePeer(command[1])
	case "disable":
		DisablePeer(command[1])
	case "remove":
		RemovePeer(command[1])
	case "export":
		ExportPeerSettings(command[1])
	}
	client.Write([]byte("Executed"))
}
