package config

type PeerConfig struct {
	Name string `json:"name"`
	Password string `json:"password"`
	VirtualIP string `json:"virtual_ip"`
	Subnet int `json:"subnet"`
	Endpoint string `json:"endpoint,omitempty"`
}

type ServerConfig struct {
	ConfigFile string
	BindAddress string `json:"bind_address"`
	VirtualIP string `json:"virtual_ip"`
	Subnet int `json:"subnet"`
	Peers []PeerConfig `json:"peers"`
}
