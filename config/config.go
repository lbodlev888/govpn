package config

type PeerConfig struct {
	Name       string   `json:"name"`
	PrivateKey string   `json:"privkey,omitempty"`
	PublicKey  string   `json:"pubkey"`
	Address    string   `json:"address"`
	Endpoint   string   `json:"endpoint,omitempty"`
	FullTunnel bool     `json:"fulltunnel,omitempty"`
	Disabled   bool     `json:"disabled,omitempty"`
	Routes     []string `json:"routes,omitempty"`
}

type ServerConfig struct {
	PrivateKey string       `json:"privkey"`
	Listen     string       `json:"listen"`
	Address    string       `json:"address"`
	Peers      []PeerConfig `json:"peers"`
}
