package winapi

import (
	"syscall"
	"unsafe"
)

var (
	pShlwapi           = syscall.NewLazyDLL("Shlwapi.dll")
	pPathFindFileNameW = pShlwapi.NewProc("PathFindFileNameW")
)

func PathFindFileNameW(path *uint16) *uint16 {
	res, _, _ := pPathFindFileNameW.Call(uintptr(unsafe.Pointer(path)))
	return (*uint16)(unsafe.Pointer(res))
}
