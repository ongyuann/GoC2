//go:build windows
// +build windows

package basic

import (
	"os/exec"
	"strings"
)

func ShellCommand(args []string) (string, error) {
	joinedArgs := strings.Join(args, " ")
	cmd := exec.Command("cmd", "/C", joinedArgs)
	result, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}
