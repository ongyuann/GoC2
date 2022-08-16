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
	go routes.StartRestAPI()
	log.Log.Info().Msg("Running RestAPI.")
	go routes.StartWebSocketServer()
	log.Log.Info().Msg("Running WebSocketServer.")
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
