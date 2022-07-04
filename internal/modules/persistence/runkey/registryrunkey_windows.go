//go:build windows
// +build windows

package runkey

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func RegistryRunKeyPersist(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	valueName := args[0]
	value := args[1]
	key, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, registry.ALL_ACCESS)
	if err != nil {
		return "", err
	}
	defer key.Close()
	err = key.SetStringValue(valueName, value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Set Run Key Values %s : %s", valueName, value), nil
}
