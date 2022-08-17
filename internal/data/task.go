package data

import (
	"encoding/json"
	"log"
)

type Task struct {
	ClientId   string   `json:"client_id"`
	OperatorId string   `json:"operator_id"`
	TaskId     string   `json:"task_id"`
	Command    string   `json:"command"`
	Args       []string `json:"args"`
	File       []byte   `json:"file"`
	Completed  bool     `json:"completed"`
}

type TaskResult struct {
	ClientId   string `json:"client_id"`
	OperatorId string `json:"operator_id"`
	TaskId     string `json:"task_id"`
	Result     string `json:"task_result"`
}

func (t *TaskResult) ToBytes() []byte {
	data, err := json.Marshal(t)
	if err != nil {
		log.Printf("Error Converting TaskResult To Bytes: %s", err.Error())
		return nil
	}
	return data
}

func (t *Task) ToBytes() []byte {
	data, err := json.Marshal(t)
	if err != nil {
		log.Printf("Error Converting Task To Bytes: %s", err.Error())
		return nil
	}
	return data
}
