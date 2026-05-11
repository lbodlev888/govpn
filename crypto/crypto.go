package crypto

import (
	"crypto/mlkem"
	"encoding/base64"
	"fmt"
	"log"
)

func GenerateCrypto() {
	decaps, err := mlkem.GenerateKey768()
	if err != nil {
		log.Fatalln("Could not generate decaps key: " + err.Error())
	}

	encaps := decaps.EncapsulationKey().Bytes()

	base64_decaps := base64.StdEncoding.EncodeToString(decaps.Bytes())
	base64_encaps := base64.StdEncoding.EncodeToString(encaps)

	fmt.Printf("Private: %s\n", base64_decaps)
	fmt.Printf("Public: %s\n", base64_encaps)
}

func GetPublicKey(pubKey string) {
	raw_decaps, err := base64.StdEncoding.DecodeString(pubKey)
	if err != nil {
		log.Fatalln("Could not decode private key: " + err.Error())
	}

	decaps, err := mlkem.NewDecapsulationKey768(raw_decaps)
	if err != nil {
		log.Fatalln("Could not import private key: " + err.Error())
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
