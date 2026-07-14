package crypto

import (
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/lbodlev888/ownvpn/proto"
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

	if len(pk) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Invalid public key size")
	}

	return ed25519.PublicKey(pk), nil
}

func DeriveEncryptionKey(material, salt []byte, infoString string, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, material, salt, infoString, length)
}

func SignClientHello(privKey ed25519.PrivateKey, h *proto.ClientHello) error {
	h.Timestamp = make([]byte, proto.TimestampLen)
	binary.BigEndian.PutUint64(h.Timestamp, uint64(time.Now().Unix()))

	payloadLen := len(h.Name) + proto.MLKEM768EncapsLen + proto.TimestampLen
	payload := make([]byte, 0, payloadLen)
	payload = append(payload, h.Name...)
	payload = append(payload, h.EncapsKey...)
	payload = append(payload, h.Timestamp...)

	signature, err := privKey.Sign(nil, payload, &ed25519.Options{Context: "clientHello"})
	if err != nil {
		return fmt.Errorf("failed to sign client hello: %w", err)
	}
	h.Signature = signature
	return nil
}

func SignServerHello(privKey ed25519.PrivateKey, h *proto.ServerHello) error {
	payload := make([]byte, 0, proto.MLKEM768CiphertextLen)
	payload = append(payload, h.Ciphertext...)

	signature, err := privKey.Sign(nil, payload, &ed25519.Options{Context: "serverHello"})
	if err != nil {
		return fmt.Errorf("failed to sign server hello: %w", err)
	}
	h.Signature = signature
	return nil
}

func CheckClientHello(pubKey ed25519.PublicKey, h proto.ClientHello) bool {
	payloadLen := len(h.Name) + proto.MLKEM768EncapsLen + proto.TimestampLen
	payload := make([]byte, 0, payloadLen)
	payload = append(payload, h.Name...)
	payload = append(payload, h.EncapsKey...)
	payload = append(payload, h.Timestamp...)

	timestamp := int64(binary.BigEndian.Uint64(h.Timestamp))
	signTime := time.Unix(timestamp, 0)
	diff := time.Since(signTime).Abs()

	return diff < 2*time.Second && ed25519.VerifyWithOptions(pubKey, payload, h.Signature, &ed25519.Options{Context: "clientHello"}) == nil
}

func CheckServerHello(pubKey ed25519.PublicKey, h proto.ServerHello) bool {
	payload := make([]byte, 0, proto.MLKEM768CiphertextLen)
	payload = append(payload, h.Ciphertext...)

	return ed25519.VerifyWithOptions(pubKey, payload, h.Signature, &ed25519.Options{Context: "serverHello"}) == nil
}
