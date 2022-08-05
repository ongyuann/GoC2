package basic

import (
	"errors"
	"os"
)

func ChangeDirectory(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("Not Enough Args")
	}
	err := os.Chdir(dir)
	path, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return path, nil
}
