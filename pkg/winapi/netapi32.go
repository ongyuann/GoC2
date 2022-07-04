package winapi

import (
	"syscall"
	"unsafe"
)

const (
	MAX_PREFFERED_LENGTH int32 = -1
)

var (
	pModNetApi32             = syscall.NewLazyDLL("Netapi32.dll")
	pNetUserEnum             = pModNetApi32.NewProc("NetUserEnum")
	pNetLocalGroupEnum       = pModNetApi32.NewProc("NetLocalGroupEnum")
	pNetLocalGroupGetMembers = pModNetApi32.NewProc("NetLocalGroupGetMembers")
	pNetGroupGetUsers        = pModNetApi32.NewProc("NetGroupGetUsers")
	pNetUserGetLocalGroups   = pModNetApi32.NewProc("NetUserGetLocalGroups")
)

func NetUserGetLocalGroups(server string, user string, level uint32, flags uint32, bufPtr uintptr, maxLen int32, entriesRead *uint32, totalEntries *uint32) (bool, error) {
	serverNamePtr, err := syscall.UTF16PtrFromString(server)
	if err != nil {
		return false, err
	}
	userName, err := syscall.UTF16PtrFromString(user)
	if err != nil {
		return false, err
	}
	res, _, _ := pNetUserGetLocalGroups.Call(uintptr(unsafe.Pointer(serverNamePtr)), uintptr(unsafe.Pointer(userName)), uintptr(level), uintptr(flags), bufPtr, uintptr(maxLen), uintptr(unsafe.Pointer(entriesRead)), uintptr(unsafe.Pointer(totalEntries)))
	if res != 0 {
		return false, nil
	}
	return true, nil
}
func NetLocalGroupEnum(server string, level uint32, bufPtr uintptr, maxLen int32, entriesRead *uint32, totalEntries *uint32, resumeHandle **uint32) (bool, error) {
	serverNamePtr, err := syscall.UTF16PtrFromString(server)
	if err != nil {
		return false, err
	}
	res, _, err := pNetLocalGroupEnum.Call(uintptr(unsafe.Pointer(serverNamePtr)), uintptr(level), bufPtr, uintptr(maxLen), uintptr(unsafe.Pointer(entriesRead)), uintptr(unsafe.Pointer(totalEntries)), uintptr(unsafe.Pointer(resumeHandle)))
	if res != 0 {
		return false, err
	}
	return true, nil
}

func NetUserEnum(server string, level uint32, filter uint32, bufPtr uintptr, maxLen int32, entriesRead *uint32, totalEntries *uint32, resumeHandle **uint32) (bool, error) {
	serverNamePtr, err := syscall.UTF16PtrFromString(server)
	if err != nil {
		return false, err
	}
	res, _, err := pNetUserEnum.Call(uintptr(unsafe.Pointer(serverNamePtr)), uintptr(level), uintptr(filter), bufPtr, uintptr(maxLen), uintptr(unsafe.Pointer(entriesRead)), uintptr(unsafe.Pointer(totalEntries)), uintptr(unsafe.Pointer(resumeHandle)))
	if res != 0 {
		return false, err
	}
	return true, nil
}

/*

res, _, err := winapi.NetUserEnum.Call(uintptr(0), 10, 0, uintptr(unsafe.Pointer(&test)), uintptr(MAX_PREFFERED_LENGTH), uintptr(unsafe.Pointer(&count)), uintptr(unsafe.Pointer(&entries)), uintptr(0))
	if res != 0 {
		er := windows.NetApiBufferFree((*byte)(unsafe.Pointer(test)))
		if er != nil {
			return "", er
		}
		return "", err
	}
*/
