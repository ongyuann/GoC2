package basic

import (
	"errors"
	"fmt"
	"log"
	"os"
)

func DeleteFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("Not Enough Args")
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		log.Println(err, 1)
		return "", err
	}
	err := os.Remove(path)
	if err != nil {
		log.Println(err, 2)
		return "", err
	}
	result := fmt.Sprintf("Deleted %s\n", path)
	return result, nil
}
