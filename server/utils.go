package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

func loadAllowedPeers() {
	allowedPeersMu.Lock()
	defer allowedPeersMu.Unlock()

	clear(allowedPeers)

	for _, p := range cfg.Peers {
		allowedPeers[p.Name] = p
	}
}

func checkPublicKey(pubKey string) error {
	pk, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("Invalid public key: %w", err)
	}

	if len(pk) != ed25519.PublicKeySize {
		return fmt.Errorf("Public key has invalid size")
	}

	return nil
}
