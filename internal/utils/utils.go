package utils

import (
	"encoding/json"
	"errors"

	"github.com/latortuga71/GoC2/internal/data"
)

func CheckMessage(socketData []byte) (error, string) {
	message := &data.Message{}
	err := json.Unmarshal(socketData, message)
	if err != nil {
		return nil, ""
	}
	switch message.MessageType {
	case "ChatMessage":
		return nil, "ChatMessage"
	case "Exit":
		return nil, "Exit"
	case "Error":
		return nil, "Error"
	case "OperatorCheckIn":
		return nil, "OperatorCheckIn"
	case "CheckIn":
		return nil, "CheckIn"
	case "Ping":
		return nil, "Ping"
	case "Task":
		return nil, "Task"
	case "TaskResult":
		return nil, "TaskResult"
	default:
		return errors.New("Unknown Message Type"), ""
	}
}
