package db

import (
	"log"
	"sync"

	"github.com/gorilla/websocket"
	"github.com/latortuga71/GoC2/internal/data"
)

var OperatorsDatabase *OperatorDB

type OperatorDB struct {
	sync.Mutex
	Database map[string]data.Operator
}

func NewOperatorDB() *OperatorDB {
	return &OperatorDB{
		Database: make(map[string]data.Operator),
	}
}

func init() {
	OperatorsDatabase = NewOperatorDB()
}

func (db *OperatorDB) AddOperatorTaskFailed(uuid string, result data.TaskResult) bool {
	db.Lock()
	defer db.Unlock()
	if _, ok := db.Database[uuid]; ok {
		msg := &data.Message{
			MessageType: "TaskResult",
			MessageData: result.ToBytes(),
		}
		db.Database[uuid].Conn.WriteMessage(msg.ToBytes())
		return true
	}
	return false
}

func (db *OperatorDB) AddOperatorTaskResult(uuid string, result data.TaskResult) bool {
	db.Lock()
	defer db.Unlock()
	if _, ok := db.Database[uuid]; ok {
		msg := &data.Message{
			MessageType: "TaskResult",
			MessageData: result.ToBytes(),
		}
		db.Database[uuid].Conn.WriteMessage(msg.ToBytes())
		return true
	}
	return false
}

func (db *OperatorDB) AddOperator(uuid string, op data.Operator, conn *websocket.Conn) bool {
	db.Lock()
	if _, ok := db.Database[uuid]; !ok {
		op.Conn = data.NewConnection(conn)
		db.Database[uuid] = op
		db.Unlock()
		return true
	}
	db.Unlock()
	return false
}

func (db *OperatorDB) UpdateOnline(uuid string, status bool) bool {
	db.Lock()
	if operator, ok := db.Database[uuid]; ok {
		operator.Online = status
		db.Database[uuid] = operator
		db.Unlock()
		return true
	}
	db.Unlock()
	return false
}

func (db *OperatorDB) DeleteConnection(uuid string) bool {
	db.Lock()
	defer db.Unlock()
	if _, ok := db.Database[uuid]; ok {
		if db.Database[uuid].ChatConn != nil {
			db.Database[uuid].ChatConn.CloseConnection()
		}
		if db.Database[uuid].Conn != nil {
			db.Database[uuid].Conn.CloseConnection()
		}
	} else {
		return false
	}
	delete(db.Database, uuid)
	if _, ok := db.Database[uuid]; !ok {
		return true
	}
	return true
}

func (db *OperatorDB) AddChatConnection(uuid string, conn *websocket.Conn) bool {
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		client.ChatConn = data.NewConnection(conn)
		db.Database[uuid] = client
		return true
	}
	log.Printf("Operator Not Found\n")
	return false
}

func (db *OperatorDB) BroadCastChatMessage(message []byte) {
	db.Lock()
	defer db.Unlock()
	for _, v := range db.Database {
		if v.ChatConn != nil {
			v.ChatConn.WriteMessage(message)
		}
	}
}
