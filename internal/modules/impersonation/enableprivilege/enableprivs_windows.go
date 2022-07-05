//go:build windows
// +build windows

package enableprivilege

import (
	"errors"
	"fmt"
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

func ShowPrivileges() (string, error) {
	// to do.
	return "", nil
}
