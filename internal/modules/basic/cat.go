package basic

import (
	"errors"
	"os"
)

func CatFile(path string) (string, error) {
	if path == "" {
		return "", errors.New("Not Enough Args")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
