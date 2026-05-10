package proto

type ClientHello struct {
	Name string `json:"name"`
	PublicData []byte `json:"public"`
}

type ServerHello struct {
	PublicData []byte `json:"public"`
	/*AssignedIP string `json:"assigned_ip"`
	ServerIP string `json:"server_ip"`
	Subnet int `json:"subnet"`*/
}
