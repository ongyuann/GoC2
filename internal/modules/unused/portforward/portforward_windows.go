//go:build windows
// +build windows

package portforward

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
)

func PortForward(args []string) (string, error) {
	if len(args) < 4 {
		return "", errors.New("Not Enough Args")
	}
	arg := fmt.Sprintf("interface portproxy add v4tov4 listenport=%s listenaddress=%s connectport=%s connectaddress=%s", args[0], args[1], args[2], args[3])
	joinedArgs := strings.Split(arg, " ")
	cmd := exec.Command("netsh", joinedArgs...)
	_, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return fmt.Sprintf("[+] Success %s", arg), nil
}

func RevertPortForward() (string, error) {
	cmd := exec.Command("netsh", "interface", "portproxy", "reset")
	_, cmdError := cmd.CombinedOutput()
	if cmdError != nil {
		return "", cmdError
	}
	return "[+] Successfully Reverted.", nil
}
