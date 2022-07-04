package modules

import "os/exec"

func CheckConstrainedLanguageMode() (string, error) {
	cmd := exec.Command("powershell.exe", "-c", "echo", "($ExecutionContext.SessionState.LanguageMode)")
	result, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return string(result), nil
}
