//go:build windows
// +build windows

package basic

import (
	"fmt"
	"strconv"

	"golang.org/x/sys/windows"
)

func KillProcess(pids string) (string, error) {
	pid, err := strconv.Atoi(pids)
	if err != nil {
		return "", err
	}
	hProc, err := windows.OpenProcess(0x1, false, uint32(pid))
	if err != nil {
		return "", err
	}
	err = windows.TerminateProcess(hProc, 0)
	if err != nil {
		return "", err
	}
	windows.CloseHandle(hProc)
	return fmt.Sprintf("Successfully killed PID %s\n", pids), nil
}
