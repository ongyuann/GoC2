//go:build darwin || linux
// +build darwin linux

package basic

import (
	"fmt"
	"strconv"
	"syscall"
)

func KillProcess(pids string) (string, error) {
	if pids == "" {
		return "", errors.New("Not Enough Args")
	}
	pid, err := strconv.Atoi(pids)
	if err != nil {
		return "", err
	}
	err = syscall.Kill(pid, syscall.SIGKILL)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Successfully killed PID %d\n", pid), nil
}
