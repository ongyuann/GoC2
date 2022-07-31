package crontab

import (
	"fmt"
	"os/exec"
)

func AppendCronJob(command string) (string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("crontab -l | { cat; echo \"0 * * * * %s\"; } | crontab - ", command))
	result, cmdError := cmd.Output()
	if cmdError != nil {
		return "", cmdError
	}
	cmd = exec.Command("crontab", "-l")
	result, cmdError = cmd.Output()
	if cmdError != nil {
		return "", cmdError
	}
	return fmt.Sprintf("[+] Added Entry\n%s\n", string(result)), nil
}
