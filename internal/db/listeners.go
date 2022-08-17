package db

import (
	"fmt"
	"sync"

	"github.com/latortuga71/GoC2/internal/data"
)

var ListenerDatabase *ListenerDB

type ListenerDB struct {
	sync.Mutex
	Database map[string]data.Listener `json:"Database"`
}

func init() {
	ListenerDatabase = NewListenerDB()
	ListenerDatabase.AddListener("Default operators websocket listener", "8443", 0) // operators socket
	ListenerDatabase.AddListener("Default rest api listener", "8000", 1)            // operators rest api
}

func NewListenerDB() *ListenerDB {
	return &ListenerDB{
		Database: make(map[string]data.Listener),
	}
}

func (db *ListenerDB) DeleteListener(port string) bool {
	db.Lock()
	defer db.Unlock()
	if l, ok := db.Database[port]; !ok {
		fmt.Printf("%s listener doesnt exist.", l.Port)
		return false
	}
	db.Database[port].ShutdownChannel <- 1
	<-db.Database[port].ShutdownChannel
	delete(db.Database, port)
	if _, ok := db.Database[port]; !ok {
		return true
	}
	return false
}

func (db *ListenerDB) AddListener(label string, port string, listenType data.ListenerType) bool {
	db.Lock()
	defer db.Unlock()
	if l, ok := db.Database[port]; ok {
		fmt.Printf("%s listener already exists.", l.Port)
		return false
	}
	db.Database[port] = data.Listener{
		Port:            port,
		Listener:        listenType,
		Label:           label,
		ShutdownChannel: make(chan int),
	}
	return true
}
