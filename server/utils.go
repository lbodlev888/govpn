package server

import (
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
)

func loadAllowedPeers() error {
	allowedPeersMu.Lock()
	defer allowedPeersMu.Unlock()

	clear(allowedPeers)

	for _, p := range cfg.Peers {
		if p.Address == "" || p.Name == "" || p.PublicKey == "" {
			return fmt.Errorf("loadAllowedPeers: peers have incomplete configs")
		}
		allowedPeers[p.Name] = p
	}

	return nil
}

func checkPublicKey(pubKey string) error {
	pk, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return fmt.Errorf("invalid public key: %w", err)
	}

	if len(pk) != ed25519.PublicKeySize {
		return fmt.Errorf("public key has invalid size")
	}

	return nil
}
