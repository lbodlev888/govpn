package models

import "net"

type Peer struct {
	Addr       *net.UDPAddr
	VirtualIP  net.IP
	SessionKey []byte
}
