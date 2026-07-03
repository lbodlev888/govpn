package server

import "net"

type peer struct {
	Addr       *net.UDPAddr
	VirtualIP  net.IP
	SessionKey []byte
	disabled bool
}
