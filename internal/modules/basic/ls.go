package basic

import (
	"fmt"
	"io/ioutil"
)

func ListDirectory(path string) (string, error) {
	var result string
	isDirStr := "<DIR>"
	if path == "" {
		path = "."
	}
	files, err := ioutil.ReadDir(path)
	if err != nil {
		return "", err
	}
	for _, file := range files {
		if file.IsDir() {
			result += fmt.Sprintf("%s %s %s %d %s \n", file.ModTime(), file.Mode().Perm().String(), isDirStr, file.Size(), file.Name())
			continue
		}
		result += fmt.Sprintf("%s %s %d %s \n", file.ModTime(), file.Mode().Perm().String(), file.Size(), file.Name())
	}
	return result, nil
}
