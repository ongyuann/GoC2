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
	ntOpenProcess, _             = bpGlobal.GetSysID("NtOpenProcess")
	ntFreeVirtualMemory, _       = bpGlobal.GetSysID("NtFreeVirtualMemory")
)

type ClientID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type ObjectAttrs struct {
	Length                   uintptr
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uintptr
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

const (
	ThisThread = uintptr(0xffffffffffffffff) //special macro that says 'use this thread/process' when provided as a handle.
	MemCommit  = uintptr(0x00001000)
	Memreserve = uintptr(0x00002000)
)

func NtOpenProcess(targetPID uint32, requestRights uint32) (uintptr, error) {
	var targetHandle uintptr
	r1, _ := bananaphone.Syscall(ntOpenProcess, uintptr(unsafe.Pointer(&targetHandle)), uintptr(requestRights), uintptr(unsafe.Pointer(&ObjectAttrs{0, 0, 0, 0, 0, 0})), uintptr(unsafe.Pointer(&ClientID{uintptr(targetPID), 0})), 0)
	if r1 != 0 {
		return 0, fmt.Errorf("NtOpenProcess error code: %x", r1)
	}
	return targetHandle, nil
}

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

func NtFreeVirtualMemory(hProcess uintptr, baseAddress uintptr, dwSize uint64, freeType uint32) (uintptr, error) {
	r1, r := bananaphone.Syscall(ntFreeVirtualMemory, hProcess, uintptr(unsafe.Pointer(&baseAddress)), uintptr(unsafe.Pointer(&dwSize)), uintptr(freeType))
	if r != nil {
		return 0, fmt.Errorf("NtFreeVirtualMemory error code: %x %s", r, r1)
	}
	return 1, nil
}
func NtAllocateVirtualMemory(hProcess uintptr, lpAddress uintptr, zerobits uint32, dwSize uint64, flAllocationType uint32, flProtect uint32) (addr uintptr, err error) {
	r1, r := bananaphone.Syscall(ntAllocateVirtualMemoryId, uintptr(hProcess), uintptr(unsafe.Pointer(&lpAddress)), 0, uintptr(unsafe.Pointer(&dwSize)), uintptr(flAllocationType), uintptr(flProtect))
	if r != nil {
		return 0, fmt.Errorf("NtAllocateVirtualMemory error code: %x %s", r, r1)
	}
	return lpAddress, err
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
