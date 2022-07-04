package data

import (
	"encoding/json"
	"log"
)

type Message struct {
	MessageType string `json:"message_type"`
	MessageData []byte `json:"message_data"`
}

func (m *Message) ToBytes() []byte {
	data, err := json.Marshal(m)
	if err != nil {
		log.Printf("Error Converting Message To Bytes: %s", err.Error())
		return nil
	}
	return data
}
