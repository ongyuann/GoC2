package basic

import (
	"errors"
	"fmt"
	"os"
)

func DeleteDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.New("Not Enough Args")
	}
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	err := os.RemoveAll(path)
	if err != nil {
		return "", err
	}
	result := fmt.Sprintf("Deleted %s Directory\n", path)
	return result, nil
}
