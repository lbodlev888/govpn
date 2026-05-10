package proto

type ClientHello struct {
	Name string `json:"name"`
	PublicKey []byte `json:"public_key"`
}

type ServerHello struct {
	PublicKey []byte `json:"public_key"`
	/*AssignedIP string `json:"assigned_ip"`
	ServerIP string `json:"server_ip"`
	Subnet int `json:"subnet"`*/
}
