package data

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"log"
)

type Operator struct {
	OperatorNick           string          `json:"operator_nick"`
	Online                 bool            `json:"online"`
	Conn                   *Connection     `json:"-"`
	ChatConn               *Connection     `json:"-"`
	InChatRoom             bool            `json:"-"`
	OperatorCertPem        string          `json:"-"`
	OperatorKeyPem         string          `json:"-"`
	OperatorRootCa         string          `json:"-"`
	OperatorCaCertPool     *x509.CertPool  `json:"-"`
	OperatorTLSCertificate tls.Certificate `json:"-"`
}

func NewOperator(nick string) *Operator {
	return &Operator{
		OperatorNick: nick,
		Online:       true,
	}
}
func (o *Operator) ToBytes() []byte {
	data, err := json.Marshal(o)
	if err != nil {
		log.Printf("Error Converting Client To Bytes: %s", err.Error())
		return nil
	}
	return data
}
