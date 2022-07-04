// +build darwin linux

package basic

import (
	"os/exec"
	"strings"
)

func ShellCommand(args []string) (string, error) {
	joinedArgs := strings.Join(args, " ")
	cmd := exec.Command("bash", "-c", joinedArgs)
	result, cmdError := cmd.Output()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}
