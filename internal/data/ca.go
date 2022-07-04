package data

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log"
	"math/big"
	"net"
	"os"
	"time"
)

///// https://github.com/haoel/mTLS/blob/main/server.go
type CertAuthority struct {
	CertData      *x509.Certificate
	CAPrivateKey  *rsa.PrivateKey
	CACertificate []byte
}

func NewCertAuthority() (*CertAuthority, error) {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	caBytes, err := x509.CreateCertificate(rand.Reader, ca, ca, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, err
	}
	rootCa := &CertAuthority{
		CertData:      ca,
		CAPrivateKey:  caPrivKey,
		CACertificate: caBytes,
	}
	return rootCa, nil
}

func (ca *CertAuthority) PemEncodeCert(data []byte) *bytes.Buffer {
	dataBytes := new(bytes.Buffer)
	pem.Encode(dataBytes, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: data,
	})
	return dataBytes

}

func (ca *CertAuthority) PemEncodeKey(key *rsa.PrivateKey) *bytes.Buffer {
	dataBytes := new(bytes.Buffer)
	pem.Encode(dataBytes, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	})
	return dataBytes
}

func (ca *CertAuthority) WriteBytesToFile(filePath string, dataBytes *bytes.Buffer) error {
	fptr, err := os.Create(filePath)
	if err != nil {
		return err
	}
	_, err = fptr.Write(dataBytes.Bytes())
	if err != nil {
		return err
	}
	fptr.Close()
	return nil
}

func (ca *CertAuthority) GenerateSignedServerCertificate() ([]byte, *rsa.PrivateKey, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	//create private key for cert
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	//sign cert with ca
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.CertData, &certPrivKey.PublicKey, ca.CAPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return certBytes, certPrivKey, nil
}

func (ca *CertAuthority) GenerateSignedClientCertificate() ([]byte, *rsa.PrivateKey, error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	//create private key for cert
	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}
	//sign cert with ca
	certBytes, err := x509.CreateCertificate(rand.Reader, cert, ca.CertData, &certPrivKey.PublicKey, ca.CAPrivateKey)
	if err != nil {
		return nil, nil, err
	}
	return certBytes, certPrivKey, nil
}

func (ca *CertAuthority) CreateWriteClientCertsToBuffers() (*bytes.Buffer, *bytes.Buffer, error) {
	certBytes, rsaPrivKey, err := ca.GenerateSignedClientCertificate()
	if err != nil {
		return nil, nil, err
	}
	keyBuffer := ca.PemEncodeKey(rsaPrivKey)
	certBuffer := ca.PemEncodeCert(certBytes)
	return keyBuffer, certBuffer, nil
}

func (ca *CertAuthority) CreateWriteClientCertsToDisk() error {
	certBytes, rsaPrivKey, err := ca.GenerateSignedClientCertificate()
	if err != nil {
		return err
	}
	keyBuffer := ca.PemEncodeKey(rsaPrivKey)
	certBuffer := ca.PemEncodeCert(certBytes)
	err = ca.WriteBytesToFile("../certs/client.key", keyBuffer)
	err = ca.WriteBytesToFile("../certs/client.cert", certBuffer)
	if err != nil {
		return err
	}
	return nil
}

func (ca *CertAuthority) CreateWriteServerCertsToDisk() error {
	certBytes, rsaPrivKey, err := ca.GenerateSignedServerCertificate()
	if err != nil {
		return err
	}
	caCertBuffer := ca.PemEncodeCert(ca.CACertificate)
	keyBuffer := ca.PemEncodeKey(rsaPrivKey)
	certBuffer := ca.PemEncodeCert(certBytes)
	err = ca.WriteBytesToFile("../certs/ca.cert", caCertBuffer)
	err = ca.WriteBytesToFile("../certs/server.key", keyBuffer)
	err = ca.WriteBytesToFile("../certs/server.cert", certBuffer)
	if err != nil {
		return err
	}
	log.Printf("Generated Signed Server Certificates.\n")
	return nil
}
