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
