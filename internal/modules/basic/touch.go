package basic

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

func Touch(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	filePath := args[0]
	fileContents := args[1:]
	contents := strings.Join(fileContents, " ")
	_, err := os.Stat(filePath)
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	file, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	wrote, err := file.WriteString(contents)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Wrote %d bytes to %s", wrote, filePath), nil
}
