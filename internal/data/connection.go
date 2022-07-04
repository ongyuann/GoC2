package data

import (
	"sync"

	"github.com/gorilla/websocket"
)

type Connection struct {
	sync.Mutex
	Conn *websocket.Conn
}

func NewConnection(c *websocket.Conn) *Connection {
	return &Connection{
		Conn: c,
	}
}

func (c *Connection) CloseConnection() {
	c.Lock()
	defer c.Unlock()
	c.Conn.Close()
}

func (c *Connection) WriteMessage(data []byte) error {
	c.Lock()
	defer c.Unlock()
	return c.Conn.WriteMessage(websocket.TextMessage, data)
}

func (c *Connection) ReadMessage() ([]byte, error) {
	//c.Lock()
	_, msg, err := c.Conn.ReadMessage()
	//c.Unlock()
	return msg, err
}
