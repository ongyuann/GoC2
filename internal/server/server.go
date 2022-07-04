package server

import (
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
	"github.com/latortuga71/wsC2/internal/data"
	"github.com/latortuga71/wsC2/internal/db"
	"github.com/latortuga71/wsC2/internal/log"
)

var ServerInterrupt chan os.Signal
var ServerDone chan interface{}
var ServerCaStarted chan interface{}
var ServerCertificateAuthority *data.CertAuthority
var ServerSharedSecret string
var ServerCertPool *x509.CertPool

func init() {
	ServerCertPool = x509.NewCertPool()
	ServerInterrupt = make(chan os.Signal)
	ServerDone = make(chan interface{})
	ServerCaStarted = make(chan interface{})
	signal.Notify(ServerInterrupt, os.Interrupt)
}
func ServerHandleTaskResult(clientUUId string, message []byte) bool {
	m := &data.Message{}
	err := json.Unmarshal(message, m)
	if err != nil {
		log.Log.Error().Msgf("Error reading task result into json %+v", err)
		return false
	}
	r := &data.TaskResult{}
	err = json.Unmarshal(m.MessageData, r)
	if err != nil {
		log.Log.Error().Msgf("Error reading task result into json %+v", err)
		return false
	}
	if op, ok := db.OperatorsDatabase.Database[r.OperatorId]; ok {
		log.Log.Debug().Msg("Found Operator To Relay Result To.")
		db.OperatorsDatabase.AddOperatorTaskResult(r.OperatorId, *r)
		log.Log.Debug().Msgf("Sent result to %s\n", op.OperatorNick)
	} else {
		log.Log.Error().Msg("Failed to find operator id")
	}
	if _, ok := db.ClientsDatabase.Database[r.ClientId]; ok {
		log.Log.Debug().Msg("Found Client")
		db.ClientsDatabase.AddClientTaskResult(r.ClientId, *r)
		log.Log.Debug().Msg("Added task result to client db")
		return true
	}
	log.Log.Info().Msg("Could not relay task to client, client not found!")
	return false
}

func ServerHandleTask(message []byte) bool {
	m := &data.Message{}
	err := json.Unmarshal(message, m)
	if err != nil {
		log.Log.Error().Msgf("Error reading task into json %+v", err)
		return false
	}
	t := &data.Task{}
	err = json.Unmarshal(m.MessageData, t)
	if err != nil {
		log.Log.Error().Msgf("Error reading task into json %+v", err)
		return false
	}
	if _, ok := db.ClientsDatabase.Database[t.ClientId]; ok {
		log.Log.Debug().Msg("Found Client")
		data := data.Message{
			MessageType: "Task",
			MessageData: t.ToBytes(),
		}
		ok := db.ClientsDatabase.AddClientTask(t.ClientId, *t)
		if !ok {
			log.Log.Error().Msg("Failed to add task to client database")
			return false
		}
		ok = db.ClientsDatabase.SendMessage(t.ClientId, data.ToBytes())
		if !ok {
			log.Log.Error().Msg("Failed to send task to client")
			return false
		}
		// May Remove
		chatMsg := fmt.Sprintf("[ %s ] <_%s_>: TASKED %s COMMAND -> %s", time.Now().Format(time.RFC1123), t.OperatorId, t.Command, t.ClientId)
		db.OperatorsDatabase.BroadCastChatMessage([]byte(chatMsg))
		return true
	}
	// something that sends the operator an error.
	log.Log.Info().Msg("Client Not Found!")
	return false

}

func ServerHandleOperatorCheckIn(operatorUUID string, message []byte, conn *websocket.Conn) *data.Message {
	m := &data.Message{}
	o := &data.Operator{}
	err := json.Unmarshal(message, m)
	if err != nil {
		log.Log.Error().Msgf("Error Handling CheckIn %v", err)
		return nil
	}
	err = json.Unmarshal(m.MessageData, o)
	if err != nil {
		log.Log.Error().Msgf("Error Handling Operator CheckIn %v", err)
		return nil
	}
	o.OperatorNick = operatorUUID
	o.Online = true
	ok := db.OperatorsDatabase.AddOperator(operatorUUID, *o, conn)
	if !ok {
		log.Log.Error().Msgf("Failed to add new operator %s", o.OperatorNick)
		return nil
	}
	msg := &data.Message{
		MessageType: "OperatorCheckIn",
		MessageData: o.ToBytes(),
	}
	log.Log.Debug().Msgf("Checked in new operator %s", o.OperatorNick)
	return msg
}

func ServerHandleCheckIn(clientUUID string, message []byte, clientConnection *websocket.Conn) *data.Message {
	m := &data.Message{}
	c := &data.Client{}
	err := json.Unmarshal(message, m)
	if err != nil {
		log.Log.Error().Msgf("Error Handling CheckIn %v\n", err)
		return nil
	}
	err = json.Unmarshal(m.MessageData, c)
	if err != nil {
		log.Log.Error().Msgf("Error Handling CheckIn %v\n", err)
		return nil
	}
	c.ClientId = clientUUID
	c.Online = true
	ok := db.ClientsDatabase.AddClient(clientUUID, *c, clientConnection)
	if !ok {
		log.Log.Error().Msgf("Failed to add client to database %v\n", err)
		return nil
	}
	chatMsg := fmt.Sprintf("[ %s ] <_%s_>: Joined the server.", time.Now().Format(time.RFC1123), clientUUID)
	db.OperatorsDatabase.BroadCastChatMessage([]byte(chatMsg))
	msg := &data.Message{
		MessageType: "CheckIn",
		MessageData: c.ToBytes(),
	}
	log.Log.Debug().Msgf("Checked in new client %s", c.ClientId)
	return msg
}

func ServerCleanClientConnections() {
	log.Log.Debug().Msg("Cleaning Up Inactive Connections...")
	data := []byte("u there?")
	var operatorsThatLeft []string
	var clientsThatLeft []string
	// could add a clients that left message to the chat just like operators below.
	for key, client := range db.ClientsDatabase.Database {
		err := client.WSConn.WriteMessage(data)
		if err != nil {
			log.Log.Debug().Msgf("Removing %s Client From List\n", key)
			db.ClientsDatabase.DeleteConnection(key)
			log.Log.Debug().Msgf("Cant Reach Client Closing Connection: %s", err)
			db.ClientsDatabase.UpdateClientOnline(key, false)
			clientsThatLeft = append(clientsThatLeft, key)
		} else {
			log.Log.Debug().Msgf("Updated Client %s Last Seen Time.", key)
			db.ClientsDatabase.UpdateClientLastSeen(key)
		}
	}
	// Operators that left the server
	for key, operator := range db.OperatorsDatabase.Database {
		err := operator.Conn.WriteMessage(data)
		if err != nil {
			log.Log.Debug().Msgf("Removing %s Operator From List\n", key)
			db.OperatorsDatabase.DeleteConnection(key)
			log.Log.Debug().Msgf("Cant Reach Operator Closing Connection: %s", err)
			db.OperatorsDatabase.UpdateOnline(key, false)
			operatorsThatLeft = append(operatorsThatLeft, key)
		}
	}
	// send message about who left
	for key, operator := range db.OperatorsDatabase.Database {
		for i := range operatorsThatLeft {
			message := fmt.Sprintf("[ %s ] <_%s_>: Left the server.", time.Now().Format(time.RFC1123), operatorsThatLeft[i])
			err := operator.ChatConn.WriteMessage([]byte(message))
			if err != nil {
				log.Log.Debug().Msgf("Removing %s Operator From List\n", key)
				db.OperatorsDatabase.DeleteConnection(key)
				log.Log.Debug().Msgf("Cant Reach Operator Closing Connection: %s", err)
				db.OperatorsDatabase.UpdateOnline(key, false)
			}
		}
		for i := range clientsThatLeft {
			message := fmt.Sprintf("[ %s ] <_%s_>: Left the server.", time.Now().Format(time.RFC1123), clientsThatLeft[i])
			err := operator.ChatConn.WriteMessage([]byte(message))
			if err != nil {
				log.Log.Debug().Msgf("Removing %s Operator From List\n", key)
				db.OperatorsDatabase.DeleteConnection(key)
				log.Log.Debug().Msgf("Cant Reach Operator Closing Connection: %s", err)
				db.OperatorsDatabase.UpdateOnline(key, false)
			}
		}
	}
}

func ServerShutDownAllConnections() {
	for key, _ := range db.ClientsDatabase.Database {
		exitMessage := data.Message{
			MessageType: "Exit",
			MessageData: data.NewExit(0).ToBytes(),
		}
		ok := db.ClientsDatabase.SendMessage(key, exitMessage.ToBytes())
		if !ok {
			time.Sleep(time.Second * 5)
			log.Log.Debug().Msgf("Removing %s Client From List\n", key)
			db.ClientsDatabase.DeleteConnection(key)
			db.ClientsDatabase.UpdateClientOnline(key, false)
		}
	}
}
