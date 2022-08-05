package basic

import (
	"errors"
	"fmt"
	"os"
)

func CreateDirectory(path string) (string, error) {
	if path == "" {
		return "", errors.New("Not Enough Args")
	}
	err := os.Mkdir(path, 0755)
	if err != nil {
		return "", err
	}
	result := fmt.Sprintf("Created %s Directory\n", path)
	return result, nil
}
