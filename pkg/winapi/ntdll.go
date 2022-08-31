package winapi

import (
	"log"
	"syscall"
	"unsafe"
)

var (
	PModNtdll               = syscall.NewLazyDLL("ntdll.dll")
	pRtlCopyMemory          = PModNtdll.NewProc("RtlCopyMemory")
	pNtProtectVirtualMemory = PModNtdll.NewProc("NtProtectVirtualMemory")
	PNtCreateThread         = PModNtdll.NewProc("NtCreateThread")
)

func NtProtectVirtualMemory(hProcess uintptr, baseAddr uintptr, bytesToProtect *uintptr, newProt uint32, oldProt *uint32) error {
	ntstatus, _, _ := pNtProtectVirtualMemory.Call(hProcess, uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(bytesToProtect)), uintptr(newProt), uintptr(unsafe.Pointer(oldProt)))
	if ntstatus != 0 {
		log.Printf("%x", ntstatus)
		return syscall.GetLastError()
	}
	log.Println("nt prot worked")
	return nil
}

// /	_, _, err = windows.RtlCopyMemory.Call(heap, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(shellcodeLen))
func RtlCopyMemory(destination uintptr, source uintptr, length uint32) error {
	//uintptr(unsafe.Pointer(&shellcode[0]))
	_, _, err := pRtlCopyMemory.Call(destination, source, uintptr(length))
	if err != nil {
		return err
	}
	return nil
}
