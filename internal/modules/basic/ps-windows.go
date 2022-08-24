//go:build windows
// +build windows

package basic

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func ListProcesses() (string, error) {
	var procs []string
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
		hProc, err := windows.OpenProcess(winapi.PROCESS_QUERY_LIMITED_INFORMATION, false, pe32.ProcessID)
		if err != nil {
			procs = append(procs, fmt.Sprintf("%d %d %s %s", pe32.ParentProcessID, pe32.ProcessID, "Acess Denied", name))
			continue
		}
		var token windows.Token
		err = windows.OpenProcessToken(hProc, winapi.TOKEN_QUERY, &token)
		if err != nil {
			procs = append(procs, fmt.Sprintf("%d %d %s %s", pe32.ParentProcessID, pe32.ProcessID, "Acess Denied", name))
			windows.CloseHandle(hProc)
			continue
		}
		user, err := token.GetTokenUser()
		if err != nil {
			procs = append(procs, fmt.Sprintf("%d %d %s %s", pe32.ParentProcessID, pe32.ProcessID, "Acess Denied", name))
			token.Close()
			windows.CloseHandle(hProc)
			continue
		}
		var nameLen uint32
		var domainLen uint32
		var use uint32
		err = windows.LookupAccountSid(nil, user.User.Sid, nil, &nameLen, nil, &domainLen, &use)
		if nameLen == 0 || domainLen == 0 {
			procs = append(procs, fmt.Sprintf("%d %d %s %s", pe32.ParentProcessID, pe32.ProcessID, "Acess Denied", name))
			token.Close()
			windows.CloseHandle(hProc)
			continue
		}
		nameBuffer := make([]uint16, nameLen)
		domainBuffer := make([]uint16, domainLen)
		err = windows.LookupAccountSid(nil, user.User.Sid, &nameBuffer[0], &nameLen, &domainBuffer[0], &domainLen, &use)
		if err != nil {
			procs = append(procs, fmt.Sprintf("%d %d %s %s", pe32.ParentProcessID, pe32.ProcessID, "Acess Denied", name))
			token.Close()
			windows.CloseHandle(hProc)
		}
		userName := fmt.Sprintf("%s\\%s", windows.UTF16PtrToString(&domainBuffer[0]), windows.UTF16PtrToString(&nameBuffer[0]))
		token.Close()
		windows.CloseHandle(hProc)
		procs = append(procs, fmt.Sprintf("%d %d %s %s", pe32.ParentProcessID, pe32.ProcessID, userName, name))
	}
	windows.CloseHandle(hSnapshot)
	return strings.Join(procs, "\n"), nil
}
