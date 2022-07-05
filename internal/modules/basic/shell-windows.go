//go:build windows
// +build windows

package basic

import (
	"os/exec"
	"strings"
	"syscall"
)

func ShellCommand(args []string) (string, error) {
	joinedArgs := strings.Join(args, " ")
	cmd := exec.Command("cmd", "/C", joinedArgs)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	result, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}
