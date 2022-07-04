//go:build windows
// +build windows

package shellhistory

import (
	"errors"
	"os"
)

func GetShellHistory() (string, error) {
	appdata, ok := os.LookupEnv("APPDATA")
	if !ok {
		return "", errors.New("Failed to get appdata env variable")
	}
	path := appdata + `\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
