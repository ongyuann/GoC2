//go:build windows
// +build windows

package basic

import (
	"os/exec"
	"syscall"
)

func ShellCommand(args []string) (string, error) {
	fixedArgs := make([]string, len(args)+1)
	fixedArgs[0] = "/c"
	for x := 1; x < len(args); x++ {
		fixedArgs[x] = args[x]
	}
	cmd := exec.Command("cmd", fixedArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	result, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}
