package proto

import (
	"crypto/rand"
	"fmt"
)

const (
	MsgClientHello byte = iota + 1
	MsgServerHello
	MsgData
	MsgKeepAlive
	MsgKeepAliveSYN
	MsgKeepAliveACK
	MsgClientConfirm

	// ML-KEM-768 ciphertext length (fixed).
	MLKEM768CiphertextLen = 1088
	MLKEM768EncapsLen = 1184
	ED25519SignatureSize = 64
	TimestampLen = 8

	MaxNameLen = 255
)

type ClientHello struct {
	Name       string
	EncapsKey []byte
	Timestamp []byte
	Signature []byte
}

type ServerHello struct {
	Ciphertext []byte
	Signature []byte
}

func EncodeKeepAlive(flag byte) []byte {
	buf := make([]byte, 5)
	buf[0] = MsgKeepAlive
	buf[1] = flag
	rand.Read(buf[2:])

	return buf
}

func DecodeKeepAlive(buf []byte, expected_flag byte) bool {
	if len(buf) != 5 || buf[0] != MsgKeepAlive {
		return false
	}
	return buf[1] == expected_flag
}

func EncodeClientHello(h ClientHello) ([]byte, error) {
	if len(h.Name) == 0 || len(h.Name) > MaxNameLen {
		return nil, fmt.Errorf("invalid name length %d", len(h.Name))
	}
	if len(h.Signature) != ED25519SignatureSize {
		return nil, fmt.Errorf("invalid signature length %d", len(h.Signature))
	}
	if len(h.EncapsKey) != MLKEM768EncapsLen {
		return nil, fmt.Errorf("invalid public data length %d", len(h.EncapsKey))
	}
	if len(h.Timestamp) != TimestampLen {
		return nil, fmt.Errorf("invalid timestamp length %d", len(h.Timestamp))
	}

	buf := make([]byte, 0, 2 + len(h.Name) + MLKEM768EncapsLen + TimestampLen + ED25519SignatureSize)
	buf = append(buf, MsgClientHello)
	buf = append(buf, byte(len(h.Name)))
	buf = append(buf, h.Name...)
	buf = append(buf, h.EncapsKey...)
	buf = append(buf, h.Timestamp...)
	buf = append(buf, h.Signature...)
	return buf, nil
}

func DecodeClientHello(buf []byte) (ClientHello, error) {
	if len(buf) < 1258 || buf[0] != MsgClientHello { //minimal clientHello has to be at least 1258 cause of 2 + timestamp + signature + encaps key
		return ClientHello{}, fmt.Errorf("not a clientHello")
	}
	nameLen := int(buf[1])
	if nameLen < 1 {
		return ClientHello{}, fmt.Errorf("client name is empty")
	}

	if len(buf) != 2 + nameLen + MLKEM768EncapsLen + TimestampLen + ED25519SignatureSize {
		return ClientHello{}, fmt.Errorf("malformed ClientHello: got %d bytes", len(buf))
	}
	return ClientHello{
		Name:       string(buf[2 : 2+nameLen]),
		EncapsKey: append([]byte(nil), buf[2+nameLen:2+nameLen+MLKEM768EncapsLen]...),
		Timestamp: append([]byte(nil), buf[2+nameLen+MLKEM768EncapsLen:2+nameLen+MLKEM768EncapsLen+TimestampLen]...),
		Signature: append([]byte(nil), buf[2+nameLen+MLKEM768EncapsLen+TimestampLen:]...),
	}, nil
}

func EncodeServerHello(h ServerHello) ([]byte, error) {
	if len(h.Ciphertext) != MLKEM768CiphertextLen {
		return nil, fmt.Errorf("invalid ciphertext length %d", len(h.Ciphertext))
	}
	if len(h.Signature) != ED25519SignatureSize {
		return nil, fmt.Errorf("invalid signature length %d", len(h.Signature))
	}

	buf := make([]byte, 1 + MLKEM768CiphertextLen + ED25519SignatureSize)
	buf[0] = MsgServerHello
	copy(buf[1:], h.Ciphertext)
	copy(buf[1 + MLKEM768CiphertextLen:], h.Signature)
	return buf, nil
}

func DecodeServerHello(buf []byte) (ServerHello, error) {
	if len(buf) != 1 + MLKEM768CiphertextLen + ED25519SignatureSize || buf[0] != MsgServerHello {
		return ServerHello{}, fmt.Errorf("malformed serverHello")
	}
	return ServerHello{
		Ciphertext: append([]byte(nil), buf[1:1+MLKEM768CiphertextLen]...),
		Signature: append([]byte(nil), buf[1 + MLKEM768CiphertextLen:]...),
	}, nil
}
