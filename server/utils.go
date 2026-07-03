package server

import (
	"crypto/mlkem"
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

func checkEncapsulation(encaps string) error {
	rawEncaps, err := base64.StdEncoding.DecodeString(encaps)
	if err != nil {
		return fmt.Errorf("checkEncapsulation: base64decode: %w", err)
	}

	_, err = mlkem.NewEncapsulationKey768(rawEncaps)
	return err
}
