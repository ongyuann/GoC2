package utils

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/latortuga71/GoC2/internal/data"
)

type checkMessageTest struct {
	arg1                 *data.Message
	expectedOutputError  error
	expectedOutputString string
}

var checkMessageTests = []checkMessageTest{
	{nil, errors.New("Unknown Message Type"), ""},
	{&data.Message{MessageType: ""}, errors.New("Unknown Message Type"), ""},
	{&data.Message{MessageType: "dsekgmMGKSMgk"}, errors.New("Unknown Message Type"), ""},
	{&data.Message{MessageType: "ChatMessage"}, nil, "ChatMessage"},
	{&data.Message{MessageType: "Exit"}, nil, "Exit"},
	{&data.Message{MessageType: "Error"}, nil, "Error"},
	{&data.Message{MessageType: "OperatorCheckIn"}, nil, "OperatorCheckIn"},
	{&data.Message{MessageType: "CheckIn"}, nil, "CheckIn"},
	{&data.Message{MessageType: "Ping"}, nil, "Ping"},
	{&data.Message{MessageType: "Task"}, nil, "Task"},
	{&data.Message{MessageType: "TaskResult"}, nil, "TaskResult"},
}

func TestCheckMessage(t *testing.T) {
	for _, test := range checkMessageTests {
		data, err := json.Marshal(test.arg1)
		if err != nil {
			t.Errorf("Failed to marshal test data %v", err)
		}
		outputError, output := CheckMessage(data)
		if output != test.expectedOutputString {
			t.Errorf("Output %v not equal to expected %v", outputError, test.expectedOutputError)
		}
	}
}
