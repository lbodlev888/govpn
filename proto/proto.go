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

	P256PublicLen = 65
	ED25519SignatureSize = 64
	TimestampLen = 8

	MaxNameLen = 255
)

type ClientHello struct {
	Name       string
	PublicKey []byte
	Timestamp []byte
	Signature []byte
}

type ServerHello struct {
	PublicKey []byte
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
	if len(h.PublicKey) != P256PublicLen {
		return nil, fmt.Errorf("invalid public data length %d", len(h.PublicKey))
	}
	if len(h.Timestamp) != TimestampLen {
		return nil, fmt.Errorf("invalid timestamp length %d", len(h.Timestamp))
	}

	buf := make([]byte, 0, 2 + len(h.Name) + P256PublicLen + TimestampLen + ED25519SignatureSize)
	buf = append(buf, MsgClientHello)
	buf = append(buf, byte(len(h.Name)))
	buf = append(buf, h.Name...)
	buf = append(buf, h.PublicKey...)
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

	if len(buf) != 2 + nameLen + P256PublicLen + TimestampLen + ED25519SignatureSize {
		return ClientHello{}, fmt.Errorf("malformed ClientHello: got %d bytes", len(buf))
	}
	return ClientHello{
		Name:       string(buf[2 : 2+nameLen]),
		PublicKey: append([]byte(nil), buf[2+nameLen:2+nameLen+P256PublicLen]...),
		Timestamp: append([]byte(nil), buf[2+nameLen+P256PublicLen:2+nameLen+P256PublicLen+TimestampLen]...),
		Signature: append([]byte(nil), buf[2+nameLen+P256PublicLen+TimestampLen:]...),
	}, nil
}

func EncodeServerHello(h ServerHello) ([]byte, error) {
	if len(h.PublicKey) != P256PublicLen {
		return nil, fmt.Errorf("invalid ciphertext length %d", len(h.PublicKey))
	}
	if len(h.Signature) != ED25519SignatureSize {
		return nil, fmt.Errorf("invalid signature length %d", len(h.Signature))
	}

	buf := make([]byte, 1 + P256PublicLen + ED25519SignatureSize)
	buf[0] = MsgServerHello
	copy(buf[1:], h.PublicKey)
	copy(buf[1 + P256PublicLen:], h.Signature)
	return buf, nil
}

func DecodeServerHello(buf []byte) (ServerHello, error) {
	if len(buf) != 1 + P256PublicLen + ED25519SignatureSize || buf[0] != MsgServerHello {
		return ServerHello{}, fmt.Errorf("malformed serverHello")
	}
	return ServerHello{
		PublicKey: append([]byte(nil), buf[1:1+P256PublicLen]...),
		Signature: append([]byte(nil), buf[1 + P256PublicLen:]...),
	}, nil
}
