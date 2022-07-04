//go:build windows
// +build windows

package listports

import (
	"os/exec"
)

func ListPorts() (string, error) {
	cmd := exec.Command("powershell", "-c", "Get-NetTCPConnection -State Listen")
	result, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}
