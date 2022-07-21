//go:build linux
// +build linux

package listports

import (
)

func ListPorts() (string, error) {
	return "Read /proc", nil
}

//https://unix.stackexchange.com/questions/226276/read-proc-to-know-if-a-process-has-opened-a-port
