//go:build windows
// +build windows

package basic

import (
	"bytes"
	"os/exec"
)

//powershell struct
type CMD struct {
	cmd string
}

// instance of powershell struct
// sets path
func NewCmd() *CMD {
	c, _ := exec.LookPath("cmd.exe")
	return &CMD{
		cmd: c,
	}
}

func (c *CMD) Execute(args ...string) (stdOut string, stdErr string, err error) {
	args = append([]string{"/c"}, args...)
	cmd := exec.Command(c.cmd, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	stdOut, stdErr = stdout.String(), stderr.String()
	return stdOut, stdErr, nil
}

func ShellCommand(command []string) (string, error) {
	pwsh := NewCmd()
	stdout, stderr, err := pwsh.Execute(command...)
	if err != nil {
		return "", err
	}
	var result string
	result += stdout
	result += stderr
	return string(result), nil
}
