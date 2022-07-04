//go:build windows
// +build windows

package basic

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

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
		procs = append(procs, fmt.Sprintf("%d %s", pe32.ProcessID, name))

	}
	windows.CloseHandle(hSnapshot)
	return strings.Join(procs, "\n"), nil
}
