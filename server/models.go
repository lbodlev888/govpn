package server

import (
	"net"
	"sync/atomic"

	"github.com/lbodlev888/ownvpn/proto"
)

type peer struct {
	Addr         *net.UDPAddr
	VirtualIP    net.IP
	disabled     bool
	c2sKey       []byte
	s2cKey       []byte
	lastNonceOut atomic.Uint64
	filter proto.Filter
}
