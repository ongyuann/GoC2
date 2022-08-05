package basic

import (
	"fmt"
	"os"
)

func UploadFile(fileBytes []byte, path string) (string, error) {
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	wrote, err := file.Write(fileBytes)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Wrote %d Bytes To %s", wrote, file.Name()), nil
}
