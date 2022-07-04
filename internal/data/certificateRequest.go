package data

type CertRequest struct {
	SharedSecret         string `json:"shared_secret"`
	B64ClientCertificate string `json:"client_cert"`
	B64ClientPrivateKey  string `json:"client_priv_key"`
	B64RootCaCertificate string `json:"root_ca_cert"`
}
