//go:build windows
// +build windows

package logonuser

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func LogonUserNetOnly(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args.")
	}
	domainW := args[0]
	userW := args[1]
	passW := args[2]
	var hToken syscall.Handle
	var bufferSz uint32 = 255
	buffer := make([]uint16, bufferSz)
	err := windows.GetUserNameEx(2, &buffer[0], &bufferSz)
	if err != nil {
		return "", err
	}
	ok, err := winapi.LogonUser(userW, domainW, passW, 9, 3, &hToken)
	if !ok {
		return "", err
	}
	worked, err := winapi.ImpersonateLoggedOnUser(windows.Token(hToken))
	if !worked {
		return "", err
	}
	windows.CloseHandle(windows.Handle(hToken))
	return fmt.Sprintf("NETONLY Impersonating %s\\%s", domainW, userW), nil
}

func LogonUser(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args.")
	}
	domainW := args[0]
	userW := args[1]
	passW := args[2]
	var hToken syscall.Handle
	var bufferSz uint32 = 255
	buffer := make([]uint16, bufferSz)
	err := windows.GetUserNameEx(2, &buffer[0], &bufferSz)
	if err != nil {
		return "", err
	}
	ok, err := winapi.LogonUser(userW, domainW, passW, 8, 3, &hToken)
	if !ok {
		return "", err
	}
	worked, err := winapi.ImpersonateLoggedOnUser(windows.Token(hToken))
	if !worked {
		return "", err
	}

	var bufferSz2 uint32 = 255
	buffer2 := make([]uint16, bufferSz)
	err = windows.GetUserNameEx(2, &buffer2[0], &bufferSz2)
	if err != nil {
		return "", err
	}
	newUser := windows.UTF16ToString(buffer2)
	if userW == newUser {
		return "", errors.New("Failed to impersonate user.")
	}
	return fmt.Sprintf("[+] Impersonating %s", newUser), err
}
