package proto

import (
	"fmt"
)

const (
	MsgClientHello byte = 0x01
	MsgServerHello byte = 0x02
	MsgData        byte = 0x03

	// ML-KEM-768 ciphertext length (fixed).
	MLKEM768CiphertextLen = 1088

	MaxNameLen = 255
)

type ClientHello struct {
	Name       string
	PublicData []byte
}

type ServerHello struct {
	PublicData []byte
}

func EncodeClientHello(h ClientHello) ([]byte, error) {
	if len(h.Name) == 0 || len(h.Name) > MaxNameLen {
		return nil, fmt.Errorf("invalid name length %d", len(h.Name))
	}
	if len(h.PublicData) != MLKEM768CiphertextLen {
		return nil, fmt.Errorf("invalid public data length %d", len(h.PublicData))
	}

	buf := make([]byte, 0, 2+len(h.Name)+MLKEM768CiphertextLen)
	buf = append(buf, MsgClientHello)
	buf = append(buf, byte(len(h.Name)))
	buf = append(buf, h.Name...)
	buf = append(buf, h.PublicData...)
	return buf, nil
}

func DecodeClientHello(buf []byte) (ClientHello, error) {
	if len(buf) < 2 || buf[0] != MsgClientHello {
		return ClientHello{}, fmt.Errorf("not a clientHello")
	}
	nameLen := int(buf[1])
	if len(buf) != 2+nameLen+MLKEM768CiphertextLen {
		return ClientHello{}, fmt.Errorf("malformed ClientHello: got %d bytes", len(buf))
	}
	return ClientHello{
		Name:       string(buf[2 : 2+nameLen]),
		PublicData: append([]byte(nil), buf[2+nameLen:]...),
	}, nil
}

func EncodeServerHello(h ServerHello) ([]byte, error) {
	if len(h.PublicData) != MLKEM768CiphertextLen {
		return nil, fmt.Errorf("invalid public data length %d", len(h.PublicData))
	}
	buf := make([]byte, 1+MLKEM768CiphertextLen)
	buf[0] = MsgServerHello
	copy(buf[1:], h.PublicData)
	return buf, nil
}

func DecodeServerHello(buf []byte) (ServerHello, error) {
	if len(buf) != 1+MLKEM768CiphertextLen || buf[0] != MsgServerHello {
		return ServerHello{}, fmt.Errorf("malformed serverHello")
	}
	return ServerHello{PublicData: append([]byte(nil), buf[1:]...)}, nil
}
