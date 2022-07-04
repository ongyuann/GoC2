//go:build windows
// +build windows

package admincheck

import (
	"golang.org/x/sys/windows"
)

func AdminCheck(remoteMachine string) (string, error) {
	ptr := windows.StringToUTF16Ptr(remoteMachine)
	hScHandle, err := windows.OpenSCManager(ptr, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return "Non Admin Or Not Running Elevated Process", err
	}
	windows.CloseHandle(hScHandle)
	return "Admin Or Running Elevated", nil
}
