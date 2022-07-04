package routes

import (
	"encoding/base64"
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/latortuga71/wsC2/internal/data"
	"github.com/latortuga71/wsC2/internal/log"
	"github.com/latortuga71/wsC2/internal/server"
)

func DistributeClientCertificate(c *gin.Context) {
	log.Log.Debug().Str("service", "CertificateAuthority").Msg("Client Requesting a Certificate.")
	var certRequest data.CertRequest
	c.BindJSON(&certRequest)
	if certRequest.SharedSecret != server.ServerSharedSecret {
		log.Log.Debug().Str("service", "CertificateAuthority").Msg(fmt.Sprintf("Client Provided Invalid Secret. %s", certRequest.SharedSecret))
		c.JSON(200, gin.H{"Message": "Get A Job!"})
		return
	}
	caCertPem := server.ServerCertificateAuthority.PemEncodeCert(server.ServerCertificateAuthority.CACertificate)
	certRequest.B64RootCaCertificate = base64.StdEncoding.EncodeToString(caCertPem.Bytes())
	clientKey, clientCert, err := server.ServerCertificateAuthority.CreateWriteClientCertsToBuffers()
	if err != nil {
		log.Log.Error().Str("service", "CertificateAuthority").Msg("Failed to generate client certificate.")
		c.JSON(http.StatusInternalServerError, gin.H{"Message": "Internal Server Error"})
		return
	}
	clientCertPem := base64.StdEncoding.EncodeToString(clientCert.Bytes())
	clientKeyPem := base64.StdEncoding.EncodeToString(clientKey.Bytes())
	certRequest.B64ClientCertificate = clientCertPem
	certRequest.B64ClientPrivateKey = clientKeyPem
	certRequest.SharedSecret = ""
	log.Log.Debug().Str("service", "CertificateAuthority").Msg("Client Provided Proper Secret.")
	log.Log.Debug().Str("service", "CertificateAuthority").Msg("Generated Client Certificate.")
	c.JSON(http.StatusOK, certRequest)
	return
}

func ServerGenerateClientCertToDisk() error {
	return server.ServerCertificateAuthority.CreateWriteClientCertsToDisk()
}

func StartCertificateAuthority() error {
	var err error
	server.ServerCertificateAuthority, err = data.NewCertAuthority()
	if err != nil {
		log.Log.Fatal().Err(err).Str("service", "Certificate Authority.")
	}
	err = server.ServerCertificateAuthority.CreateWriteServerCertsToDisk()
	if err != nil {
		log.Log.Fatal().Err(err).Str("service", "Certificate Authority.")
	}
	ServerGenerateClientCertToDisk()
	server.ServerCaStarted <- true
	log.Log.Debug().Str("service", "Certificate Authority").Msg("Certificate Authority Running...")
	return nil
}
