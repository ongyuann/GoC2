package main

import (
	"flag"
	"os"
	"time"

	"github.com/latortuga71/GoC2/internal/log"
	"github.com/latortuga71/GoC2/internal/routes"
	"github.com/latortuga71/GoC2/internal/server"
)

func main() {
	// setup
	debug := flag.Bool("debug", false, "sets log level to debug")
	secret := flag.String("secret", "", "set the (16 Byte) secret that is needed to acquire a client certificate.")
	restPort := flag.String("rest", "8000", "set port for rest api")
	operatorsWSPort := flag.String("ws", "8443", "set port for operators websocket connection")
	flag.Parse()
	log.SetLevelInfo()
	if *debug {
		routes.DebugMode = true
		log.SetLevelDebug()
	}
	if *secret == "" {
		log.Log.Info().Msg("Missing -secret parameter.")
		flag.PrintDefaults()
		os.Exit(0)
	}
	if len(*secret) != 16 {
		log.Log.Info().Msg("-secret parameter must be 16 bytes long exactly.")
		flag.PrintDefaults()
		os.Exit(0)
	}
	server.ServerSharedSecret = *secret
	log.Log.Debug().Msgf("Setting Shared Secret To %s", server.ServerSharedSecret)
	log.Log.Info().Msg("Running Certificate Authority.")
	go routes.StartCertificateAuthority()
	<-server.ServerCaStarted
	go routes.StartRestAPI(*restPort)
	log.Log.Info().Msgf("Running RestAPI on %s.", *restPort)
	go routes.StartWebSocketOperatorServer(*operatorsWSPort)
	log.Log.Info().Msgf("Running WebSocketOperatorServer on %s.", *operatorsWSPort)
	for {
		select {
		case <-server.ServerInterrupt:
			log.Log.Debug().Msg("Received SIGINT interrupt signal. Closing all pending connections")
			//server.ServerShutDownAllConnections()
			close(server.ServerDone)
			select {
			case <-server.ServerDone:
				log.Log.Debug().Msg("Receiver Channel Closed! Exiting....")
			case <-time.After(time.Duration(1) * time.Second):
				log.Log.Debug().Msg("Timeout in closing receiving channel. Exiting....")
			}
			return
		}
	}
}
