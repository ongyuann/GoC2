package rawapi

import (
	"fmt"
	"unsafe"

	bananaphone "github.com/C-Sto/BananaPhone/pkg/BananaPhone"
)

// var runs before init
var (
	bpGlobal, bperr              = bananaphone.NewBananaPhone(bananaphone.AutoBananaPhoneMode)
	ntWriteVirtualMemoryId, _    = bpGlobal.GetSysID("NtWriteVirtualMemory")
	ntAllocateVirtualMemoryId, _ = bpGlobal.GetSysID("NtAllocateVirtualMemory")
	ntProtectVirtualMemoryId, _  = bpGlobal.GetSysID("NtProtectVirtualMemory")
	ntCreateThreadExId, _        = bpGlobal.GetSysID("NtCreateThreadEx")
	ntReadVirtualMemory, _       = bpGlobal.GetSysID("NtReadVirtualMemory")
	//ntOpenProcess, _             = bpGlobal.GetSysID("NtOpenProcess")
)

const (
	ThisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
	MemCommit  = uintptr(0x00001000)
	Memreserve = uintptr(0x00002000)
)

func NtReadVirtualMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer uintptr, nRead uint32, bytesRead *uint32) (err error) {
	r1, _ := bananaphone.Syscall(ntReadVirtualMemory, uintptr(hProcess), uintptr(lpBaseAddress), lpBuffer, uintptr(nRead), uintptr(unsafe.Pointer(bytesRead)))
	if r1 != 0 {
		err = fmt.Errorf("NtReadVirtualMemory error code: %x", r1)
	}
	return
}

func NtWriteVirtualMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer uintptr, nSize uintptr, lpNumberOfBytesWritten *uint32) (err error) {
	r1, _ := bananaphone.Syscall(ntWriteVirtualMemoryId, uintptr(hProcess), uintptr(lpBaseAddress), lpBuffer, uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
	if r1 != 0 {
		err = fmt.Errorf("NtWriteVirtualMemory error code: %x", r1)
	}
	return
}

func NtAllocateVirtualMemory(hProcess uintptr, lpAddress *uintptr, zerobits uint32, dwSize *uint32, flAllocationType uint32, flProtect uint32) (err error) {
	r1, _ := bananaphone.Syscall(ntAllocateVirtualMemoryId, uintptr(hProcess), uintptr(unsafe.Pointer(lpAddress)), uintptr(zerobits), uintptr(unsafe.Pointer(dwSize)), uintptr(flAllocationType), uintptr(flProtect))
	if r1 != 0 {
		err = fmt.Errorf("NtAllocateVirtualMemory error code: %x", r1)
	}
	return
}

func NtProtectVirtualMemory(hProcess uintptr, baseAddr uintptr, bytesToProtect *uintptr, newProt uint32, oldProt *uint32) (err error) {
	r1, _ := bananaphone.Syscall(ntProtectVirtualMemoryId, hProcess, uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(bytesToProtect)), uintptr(newProt), uintptr(unsafe.Pointer(oldProt)))
	if r1 != 0 {
		err = fmt.Errorf("NtProtectVirtualMemory error code: %x", r1)
	}
	return
}

func NtCreateThreadEx(hThread *uintptr, desiredaccess uintptr, objattrib uintptr, processhandle uintptr, lpstartaddr uintptr, lpparam uintptr, createsuspended uintptr, zerobits uintptr, sizeofstack uintptr, sizeofstackreserve uintptr, lpbytesbuffer uintptr) (err error) {
	r1, _ := bananaphone.Syscall(ntCreateThreadExId, uintptr(unsafe.Pointer(hThread)), uintptr(desiredaccess), uintptr(objattrib), uintptr(processhandle), uintptr(lpstartaddr), uintptr(lpparam), uintptr(createsuspended), uintptr(zerobits), uintptr(sizeofstack), uintptr(sizeofstackreserve), uintptr(lpbytesbuffer))
	if r1 != 0 {
		err = fmt.Errorf("NtCreateThreadEx error code: %x", r1)
	}
	return
}
