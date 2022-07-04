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
)

const (
	ThisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
	MemCommit  = uintptr(0x00001000)
	Memreserve = uintptr(0x00002000)
)

func NtWriteVirtualMemory(hProcess uintptr, lpBaseAddress uintptr, lpBuffer *byte, nSize uintptr, lpNumberOfBytesWritten *uintptr) (err error) {
	r1, _ := bananaphone.Syscall(ntWriteVirtualMemoryId, uintptr(hProcess), uintptr(lpBaseAddress), uintptr(unsafe.Pointer(lpBuffer)), uintptr(nSize), uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
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

func NtProtectVirtualMemory(hProcess uintptr, lpAddress *uintptr, dwSize *uintptr, flNewProtect uint32, lpflOldProtect *uint32) (err error) {
	r1, _ := bananaphone.Syscall(ntProtectVirtualMemoryId, uintptr(hProcess), uintptr(unsafe.Pointer(lpAddress)), uintptr(unsafe.Pointer(dwSize)), uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)))
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
