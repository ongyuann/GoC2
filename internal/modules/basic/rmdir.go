package basic

import (
	"errors"
	"fmt"
	"log"
	"os"
)

func DeleteDirectory(path string) (string, error) {
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		log.Println(err, 1)
		return "", err
	}
	err := os.RemoveAll(path)
	if err != nil {
		log.Println(err, 2)
		return "", err
	}
	result := fmt.Sprintf("Deleted %s Directory\n", path)
	return result, nil
}
