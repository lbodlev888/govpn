package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

func GeneratePrivate() (string, error) {
	_, sk, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("Could not generate decaps key: %w", err)
	}

	return base64.StdEncoding.EncodeToString(sk.Seed()), nil
}

func GetPublicKey(privKey string) (string, error) {
	seed, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		return "", fmt.Errorf("Invalid input private key: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return "", fmt.Errorf("Invalid input size, should be %d", ed25519.SeedSize)
	}
	sk := ed25519.NewKeyFromSeed(seed)
	pk, ok := sk.Public().(ed25519.PublicKey)
	if !ok {
		return "", fmt.Errorf("Failed to extract public key")
	}
	return base64.StdEncoding.EncodeToString(pk), nil
}

func ParsePrivateKey(privKey string) (ed25519.PrivateKey, error) {
	seed, err := base64.StdEncoding.DecodeString(privKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode private key: %w", err)
	}

	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("Invalid input size, should be %d", ed25519.SeedSize)
	}

	return ed25519.NewKeyFromSeed(seed), nil
}

func ParsePublicKey(pubKey string) (ed25519.PublicKey, error) {
	pk, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode public key: %w", err)
	}

	return ed25519.PublicKey(pk), nil
}

func DeriveEncryptionKey(material, salt []byte, infoString string, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, material, salt, infoString, length)
}
