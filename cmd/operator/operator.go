package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/gorilla/websocket"
	"github.com/latortuga71/GoC2/internal/data"
	"github.com/latortuga71/GoC2/internal/operator"
)

func main() {
	nickPtr := flag.String("nick", "", "Operator Handle")
	serverPtr := flag.String("server", "", "Server Ip/Hostname")
	secretPtr := flag.String("secret", "", "Server shared secret.")
	serverRestPort := flag.String("restPort", "8000", "Server REST Port")
	serverWSPort := flag.String("wsPort", "8443", "Server WS Port")
	flag.Parse()
	if *nickPtr == "" || *serverPtr == "" || *secretPtr == "" {
		flag.PrintDefaults()
		os.Exit(0)
	}
	operator.ServerHostName = *serverPtr
	operator.ServerSharedSecret = *secretPtr
	operator.ServerRestPort = *serverRestPort
	operator.ServerWSPort = *serverWSPort
	err := operator.InitializeOperator(*nickPtr)
	if err != nil {
		log.Fatal(err)
	}
	websocket.DefaultDialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		RootCAs:            operator.Operator.OperatorCaCertPool,
		Certificates:       []tls.Certificate{operator.Operator.OperatorTLSCertificate},
	}
	socketUrl := fmt.Sprintf("wss://%s:%s/%s", operator.ServerHostName, *serverWSPort, "socketOperator")
	c, _, err := websocket.DefaultDialer.Dial(socketUrl,
		http.Header{
			"nick":          []string{operator.Operator.OperatorNick},
			"shared-secret": []string{operator.ServerSharedSecret},
		})
	if err != nil {
		log.Fatal("Error connecting to websocket server: ", err)
	}
	operator.Operator.Conn = data.NewConnection(c)
	if err != nil {
		log.Fatal("Error connecting to Websocket Server: ", err)
	}
	go operator.OperatorReceiveHandler(operator.Operator)
	operator.OperatorDoCheckIn(operator.Operator)
	go operator.OperatorKeepAlive()
	go operator.OperatorJoinChat()
	operator.OperatorMainLoop()
}
