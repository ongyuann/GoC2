package data

import (
	"encoding/json"
	"log"
	"time"
)

// yo we never used this lol.

type ChatMessage struct {
	OperatorNick string    `json:"operator_nick"`
	Message      string    `json:"message"`
	TimeStamp    time.Time `json:"time_stamp"`
}

func (c *ChatMessage) ToBytes() []byte {
	data, err := json.Marshal(c)
	if err != nil {
		log.Printf("Error Converting ChatMessage To Bytes: %s", err.Error())
		return nil
	}
	return data
}
