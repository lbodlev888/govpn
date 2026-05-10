package models

import "net"

type Peer struct {
	Conn net.Conn
	VirtualIP net.IP
	SessionKey []byte
}
