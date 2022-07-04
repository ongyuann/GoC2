//go:build windows
// +build windows

package runbinary

import (
	"errors"
	"fmt"
	"strings"

	"golang.org/x/sys/windows"
)

func RunBinary(args []string) (string, error) {
	if len(args) < 1 {
		return "", errors.New("Not Enough Args")
	}
	binaryName, err := windows.UTF16PtrFromString(args[0])
	commandLine, err := windows.UTF16PtrFromString(strings.Join(args, " "))
	if err != nil {
		return "", err
	}
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	err = windows.CreateProcess(binaryName, commandLine, nil, nil, false, 0, nil, nil, &si, &pi)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Started Process Id %d", pi.ProcessId), nil
}
