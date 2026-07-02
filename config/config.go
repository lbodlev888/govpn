package config

type PeerConfig struct {
	Name string `json:"name"`
	DecapsKey string `json:"privkey"`
	EncapsKey string `json:"pubkey"`
	VirtualIP string `json:"virtual_ip"`
	Subnet int `json:"subnet"`
	Endpoint string `json:"endpoint,omitempty"`
	FullTunnel bool `json:"fulltunnel,omitempty"`
}

type ServerConfig struct {
	DecapsKey string `json:"privkey"`
	BindAddress string `json:"bind_address"`
	VirtualIP string `json:"virtual_ip"`
	Subnet int `json:"subnet"`
	Peers []PeerConfig `json:"peers"`
}
