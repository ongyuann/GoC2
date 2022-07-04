package basic

import (
	"fmt"
	"io/ioutil"
)

func ListDirectory(path string) (string, error) {
	var result string
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		result += fmt.Sprintf("%s\n", file.Name())
	}
	return result, nil
}
