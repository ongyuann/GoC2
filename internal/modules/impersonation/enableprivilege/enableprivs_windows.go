//go:build windows
// +build windows

package enableprivilege

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func EnablePriv(priv string) (string, error) {
	hProc := winapi.GetCurrentProcess()
	if hProc == 0 {
		return "", errors.New("Failed to get handle to current process.")
	}
	var hToken windows.Token
	var luid windows.LUID
	err := windows.OpenProcessToken(windows.Handle(hProc), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &hToken)
	if err != nil {
		return "", err
	}
	err = windows.LookupPrivilegeValue(nil, syscall.StringToUTF16Ptr(priv), &luid)
	if err != nil {
		return "", err
	}
	luAttr := windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges:     [1]windows.LUIDAndAttributes{},
	}
	tp.Privileges[0] = luAttr
	oldTp := windows.Tokenprivileges{}
	var retLen uint32
	err = windows.AdjustTokenPrivileges(hToken, false, &tp, uint32(unsafe.Sizeof(tp)), &oldTp, &retLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Enabled %s Privilege", priv), nil
}

func DisablePriv(priv string) (string, error) {
	hProc := winapi.GetCurrentProcess()
	if hProc == 0 {
		return "", errors.New("Failed to get handle to current process.")
	}
	var hToken windows.Token
	var luid windows.LUID
	err := windows.OpenProcessToken(windows.Handle(hProc), windows.TOKEN_QUERY|windows.TOKEN_ADJUST_PRIVILEGES, &hToken)
	if err != nil {
		return "", err
	}
	err = windows.LookupPrivilegeValue(nil, syscall.StringToUTF16Ptr(priv), &luid)
	if err != nil {
		return "", err
	}
	luAttr := windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: 0,
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges:     [1]windows.LUIDAndAttributes{},
	}
	tp.Privileges[0] = luAttr
	oldTp := windows.Tokenprivileges{}
	var retLen uint32
	err = windows.AdjustTokenPrivileges(hToken, false, &tp, uint32(unsafe.Sizeof(tp)), &oldTp, &retLen)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Disabled %s Privilege", priv), nil
}

func CheckPrivilege(hToken windows.Token, luid windows.LUID) bool {
	privSet := winapi.PrivilegeSet{
		PrivilegeCount: 1,
		Privilege:      [1]windows.LUIDAndAttributes{},
		Control:        winapi.PRIVILEGE_SET_ALL_NECESSARY,
	}
	privSet.Privilege[0].Luid = luid
	privSet.Privilege[0].Attributes = windows.SE_PRIVILEGE_ENABLED
	var result bool = false
	winapi.PrivilegeCheck(hToken, &privSet, &result)
	return result
}

func LookupPrivilegeDescription(privilegeName string) string {
	description, err := winapi.LookupPrivilegeDisplayName(".", privilegeName)
	if err != nil {
		return "Failed to get description"
	}
	return description
}

func ShowPrivileges() (string, error) {
	privs := fmt.Sprintf("%-45s %70s %s\n", "Privilege Name", "Description", "Status")
	privs += fmt.Sprintf("%s\n", strings.Repeat("=", 150))
	hProc := winapi.GetCurrentProcess()
	if hProc == 0 {
		return "", errors.New("Failed to get handle to current process.")
	}
	var hToken windows.Token
	err := windows.OpenProcessToken(windows.Handle(hProc), windows.TOKEN_QUERY, &hToken)
	if err != nil {
		return "", errors.New("Failed to open process token")
	}
	var retLen uint32
	windows.GetTokenInformation(hToken, windows.TokenPrivileges, nil, 0, &retLen)
	tokenPrivs := make([]byte, retLen*2)
	err = windows.GetTokenInformation(hToken, windows.TokenPrivileges, (*byte)(unsafe.Pointer(&tokenPrivs[0])), retLen, &retLen)
	if err != nil {
		return "", err
	}
	tokenPrivStruct := (*windows.Tokenprivileges)(unsafe.Pointer(&tokenPrivs[0]))
	for _, p := range tokenPrivStruct.AllPrivileges() {
		var nameSize uint32
		winapi.LookupPrivilegeNameW(".", &p.Luid, nil, &nameSize)
		if nameSize == 0 {
			continue
		}
		nameBuffer := make([]uint16, nameSize*2) // add 2 because unicode
		err = winapi.LookupPrivilegeNameW(".", &p.Luid, &nameBuffer[0], &nameSize)
		if err != nil {
			continue
		}
		result := CheckPrivilege(hToken, p.Luid)
		description := LookupPrivilegeDescription(windows.UTF16PtrToString(&nameBuffer[0]))
		privs += fmt.Sprintf("%-45s %70s %t\n", windows.UTF16PtrToString(&nameBuffer[0]), description, result)
	}
	return privs, nil
}
