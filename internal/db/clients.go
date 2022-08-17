package db

import (
	"log"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/latortuga71/GoC2/internal/data"
)

var ClientsDatabase *ClientDB

type ClientDB struct {
	sync.Mutex
	Database map[string]data.Client `json:"Database"`
}

func init() {
	ClientsDatabase = NewClientDB()
}

func NewClientDB() *ClientDB {
	return &ClientDB{
		Database: make(map[string]data.Client),
	}
}

func (db *ClientDB) AddClientTask(uuid string, task data.Task) bool {
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		client.Tasks = append(client.Tasks, task)
		db.Database[uuid] = client
		return true
	}
	return false
}

func (db *ClientDB) UpdateClientOnline(uuid string, status bool) bool {
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		client.Online = status
		db.Database[uuid] = client
		return true
	}
	return false
}

func (db *ClientDB) UpdateClientLastSeen(uuid string) bool {
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		client.LastSeen = time.Now()
		client.Online = true
		db.Database[uuid] = client
		return true
	}
	return false
}

func (db *ClientDB) ClientGetAvailableTasks(uuid string) []data.Task {
	tasks := make([]data.Task, 0)
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		for x := range client.Tasks {
			if !client.Tasks[x].Completed {
				tasks = append(tasks, client.Tasks[x])
			}
		}
	}
	return tasks
}

func (db *ClientDB) SetClientSleeping(uuid string) bool {
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		client.Sleeping = true
		db.Database[uuid] = client
	}
	return true
}

func (db *ClientDB) SetClientAwake(uuid string) bool {
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		client.Sleeping = false
		db.Database[uuid] = client
	}
	return true
}

func (db *ClientDB) SetClientJitter(uuid string, jitter string) bool {
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		j, err := strconv.Atoi(strings.Split(jitter, "\n")[0])
		if err != nil {
			log.Println(err)
			return false
		}
		client.Jitter = j
		db.Database[uuid] = client
		return true
	}
	return false
}

func (db *ClientDB) ClientSetTaskComplete(uuid string) bool {
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		for x := range client.Tasks {
			if !client.Tasks[x].Completed {
				client.Tasks[x].Completed = true
				return true
			}
		}
		return false
	}
	return false
}

func (db *ClientDB) AddClientTaskResult(uuid string, result data.TaskResult) bool {
	db.Lock()
	defer db.Unlock()
	/* to truncate big outputs.*/
	if client, ok := db.Database[uuid]; ok {
		if len(result.Result) < 1024*1024 {
			client.Results = append(client.Results, result)
			db.Database[uuid] = client
			return true
		} else {
			result.Result = result.Result[:1024] + "\n---TRUNCATED---"
			client.Results = append(client.Results, result)
			db.Database[uuid] = client
			return true
		}
	}
	// original no truncation.
	/*
		if client, ok := db.Database[uuid]; ok {
			client.Results = append(client.Results, result)
			db.Database[uuid] = client
			return true
		}
	*/
	return false
}

func (db *ClientDB) AddClient(uuid string, client data.Client, conn *websocket.Conn) bool {
	db.Lock()
	defer db.Unlock()
	if _, ok := db.Database[uuid]; !ok {
		client.WSConn = data.NewConnection(conn)
		db.Database[uuid] = client
		return true
	}
	return false
}

func (db *ClientDB) DeleteConnection(uuid string) bool {
	db.Lock()
	defer db.Unlock()
	db.Database[uuid].WSConn.CloseConnection()
	//delete(db.Database, uuid)
	/*
		if _, ok := db.Database[uuid]; !ok {
			return true
		}
	*/
	return true
}

func (db *ClientDB) SendTask(uuid string, data []byte) bool {
	db.Lock()
	defer db.Unlock()
	if client, ok := db.Database[uuid]; ok {
		if client.ListenerType == 1 {
			// client is https
			return true
		}
		err := client.WSConn.WriteMessage(data)
		if err != nil {
			return false
		}
		return true
	}
	log.Printf("client not found\n")
	return false
}
