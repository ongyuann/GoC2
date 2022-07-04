package data

import (
	"encoding/json"
	"log"
)

type Exit struct {
	ExitStatus int `json:"exit_status"`
}

func NewExit(statusCode int) *Exit {
	return &Exit{
		ExitStatus: statusCode,
	}
}

func (e *Exit) ToBytes() []byte {
	data, err := json.Marshal(e)
	if err != nil {
		log.Printf("Error Converting Exit To Bytes: %s", err.Error())
		return nil
	}
	return data
}
