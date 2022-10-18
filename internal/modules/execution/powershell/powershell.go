package powershell

import (
	"bytes"
	"os/exec"
)

//powershell struct
type PowerShell struct {
	powerShell string
}

// instance of powershell struct
// sets path
func NewPwsh() *PowerShell {
	ps, _ := exec.LookPath("powershell.exe")
	return &PowerShell{
		powerShell: ps,
	}
}

func (p *PowerShell) Execute(args ...string) (stdOut string, stdErr string, err error) {
	args = append([]string{"-WindowStyle Hidden -NoProfile", "-NonInteractive"}, args...)
	cmd := exec.Command(p.powerShell, args...)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	stdOut, stdErr = stdout.String(), stderr.String()
	return stdOut, stdErr, nil
}

func RunPwsh(command []string) (string, error) {
	pwsh := NewPwsh()
	stdout, stderr, err := pwsh.Execute(command...)
	if err != nil {
		return "", err
	}
	var result string
	result += stdout
	result += stderr
	return string(result), nil
}
