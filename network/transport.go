package network

import (
	"encoding/binary"
	"io"
	"net"
)

// shared between client and server
func WriteFrame(conn net.Conn, data []byte) error {
    hdr := make([]byte, 4)
    binary.BigEndian.PutUint32(hdr, uint32(len(data)))
    _, err := conn.Write(append(hdr, data...))
    return err
}

func ReadFrame(conn net.Conn) ([]byte, error) {
    hdr := make([]byte, 4)
    if _, err := io.ReadFull(conn, hdr); err != nil {
        return nil, err
    }
    n := binary.BigEndian.Uint32(hdr)
    buf := make([]byte, n)
    _, err := io.ReadFull(conn, buf)
    return buf, err
}
