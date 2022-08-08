//go:build windows
// +build windows

package basic

import (
	"os/exec"
	"strings"
	"syscall"
)

func ShellCommand(args string) (string, error) {
	split := strings.Split(args, " ")
	fix := make([]string, 1)
	fix[0] = "/c"
	fix = append(fix, split...)
	cmd := exec.Command("cmd", fix...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	result, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}
