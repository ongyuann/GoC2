//go:build windows
// +build windows

package basic

import (
	"fmt"
	"os"
	"syscall"
)

func MoveFile(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("Not Enough Args.")
	}
	source := args[0]
	destination := args[1]
	_, err := os.Stat(source)
	if err != nil {
		return "", err
	}
	srcPtr, err := syscall.UTF16PtrFromString(source)
	if err != nil {
		return "", err
	}
	destPtr, err := syscall.UTF16PtrFromString(destination)
	if err != nil {
		return "", err
	}
	err = syscall.MoveFile(srcPtr, destPtr)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Moved File From %s to %s", source, destination), nil
}
