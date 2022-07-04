package winapi

import (
	"syscall"
)

var (
	pModNtdll      = syscall.NewLazyDLL("ntdll.dll")
	pRtlCopyMemory = pModNtdll.NewProc("RtlCopyMemory")
)

// /	_, _, err = windows.RtlCopyMemory.Call(heap, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(shellcodeLen))
func RtlCopyMemory(destination uintptr, source uintptr, length uint32) error {
	//uintptr(unsafe.Pointer(&shellcode[0]))
	_, _, err := pRtlCopyMemory.Call(destination, source, uintptr(length))
	if err != nil {
		return err
	}
	return nil
}
