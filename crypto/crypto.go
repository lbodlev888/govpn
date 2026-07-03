package crypto

import (
	"crypto/hkdf"
	"crypto/mlkem"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
)

func GeneratePrivate() {
	decaps, err := mlkem.GenerateKey768()
	if err != nil {
		log.Println("Could not generate decaps key: " + err.Error())
		return
	}

	base64_decaps := base64.StdEncoding.EncodeToString(decaps.Bytes())

	fmt.Printf("Private: %s\n", base64_decaps)
}

func GetPublicKey(pubKey string) {
	raw_decaps, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		log.Println("Could not decode private key: " + err.Error())
		return
	}

	decaps, err := mlkem.NewDecapsulationKey768(raw_decaps)
	if err != nil {
		log.Println("Could not import private key: " + err.Error())
		return
	}

	encaps := decaps.EncapsulationKey().Bytes()

	fmt.Printf("Public: %s\n", base64.StdEncoding.EncodeToString(encaps))
}

func ParseDecapsKey(decaps_str string) (*mlkem.DecapsulationKey768, error) {
	raw_decaps, err := base64.StdEncoding.DecodeString(decaps_str)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode private key: %w", err)
	}

	return mlkem.NewDecapsulationKey768(raw_decaps)
}

func ParseEncapsKey(encaps_str string) (*mlkem.EncapsulationKey768, error) {
	raw_encaps, err := base64.StdEncoding.DecodeString(encaps_str)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode public key: %w", err)
	}

	return mlkem.NewEncapsulationKey768(raw_encaps)
}

func DeriveEncryptionKey(material, salt []byte, infoString string, length int) ([]byte, error) {
	return hkdf.Key(sha256.New, material, salt, infoString, length)
}
