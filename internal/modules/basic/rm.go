package basic

import (
	"errors"
	"fmt"
	"os"
)

func DeleteFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("Not Enough Args")
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	err := os.Remove(path)
	if err != nil {
		return "", err
	}
	result := fmt.Sprintf("Deleted %s\n", path)
	return result, nil
}
