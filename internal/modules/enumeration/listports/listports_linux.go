//go:build linux
// +build linux

package listports

import (
	"os/exec"
)

func ListPorts() (string, error) {
	return "coming soon", nil
}

//https://unix.stackexchange.com/questions/226276/read-proc-to-know-if-a-process-has-opened-a-port
