package basic

import (
	"os"
)

func ChangeDirectory(dir string) (string, error) {
	err := os.Chdir(dir)
	path, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return path, nil
}
