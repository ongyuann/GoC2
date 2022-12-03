package winapi

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	MAX_PREFFERED_LENGTH int32 = -1
	//MAX_PREFFERED_LENGTH uint32 = 0xFFFFFFFF
	ACCESS_READ   = 0x01
	ACCESS_WRITE  = 0x02
	ACCESS_CREATE = 0x04
	ACCESS_EXEC   = 0x08
	ACCESS_DELETE = 0x10
	ACCESS_ATRIB  = 0x20
	ACCESS_PERM   = 0x40
	ACCESS_ALL    = ACCESS_READ | ACCESS_WRITE | ACCESS_CREATE | ACCESS_EXEC | ACCESS_DELETE | ACCESS_ATRIB | ACCESS_PERM
)

var (
	pModNetApi32             = syscall.NewLazyDLL("Netapi32.dll")
	pNetUserEnum             = pModNetApi32.NewProc("NetUserEnum")
	pNetLocalGroupEnum       = pModNetApi32.NewProc("NetLocalGroupEnum")
	pNetLocalGroupGetMembers = pModNetApi32.NewProc("NetLocalGroupGetMembers")
	pNetGroupGetUsers        = pModNetApi32.NewProc("NetGroupGetUsers")
	pNetUserGetLocalGroups   = pModNetApi32.NewProc("NetUserGetLocalGroups")
	pNetApiBufferAllocate    = pModNetApi32.NewProc("NetApiBufferAllocate")
	pNetApiBufferFree        = pModNetApi32.NewProc("NetApiBufferFree")
	pNetLocalGroupAddMembers = pModNetApi32.NewProc("NetLocalGroupAddMembers")
	pNetLocalGroupDelMembers = pModNetApi32.NewProc("NetLocalGroupDelMembers")
	pNetUserAdd              = pModNetApi32.NewProc("NetUserAdd")
	pNetUserDel              = pModNetApi32.NewProc("NetUserDel")
	pNetServerEnum           = pModNetApi32.NewProc("NetServerEnum")
	pNetWkstaUserEnum        = pModNetApi32.NewProc("NetWkstaUserEnum")
	pNetShareEnum            = pModNetApi32.NewProc("NetShareEnum")
	pNetShareAdd             = pModNetApi32.NewProc("NetShareAdd")
	pNetShareDel             = pModNetApi32.NewProc("NetShareDel")
)

func NetShareAdd(server string, level uint32, bufPtr *SHARE_INFO_2) error {
	s, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return err
	}
	var t uint32
	res, _, err := pNetShareAdd.Call(uintptr(unsafe.Pointer(s)), uintptr(2), uintptr(unsafe.Pointer(bufPtr)), uintptr(unsafe.Pointer(&t)))
	if res != 0 {
		return fmt.Errorf("Error Code 0x%x", res)
	}
	return nil
}

func NetShareEnum(server string, bufPtr **SHARE_INFO_2, maxLen int32, entries *uint32, total *uint32) error {
	s, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return err
	}
	res, _, err := pNetShareEnum.Call(uintptr(unsafe.Pointer(s)), uintptr(2), uintptr(unsafe.Pointer(bufPtr)), uintptr(maxLen), uintptr(unsafe.Pointer(entries)), uintptr(unsafe.Pointer(total)), uintptr(0))
	if res != 0 {
		return err
	}
	return nil
}

func NetWkstaUserEnum(server string, bufPtr **WKSTA_USER_INFO_1, maxLen int32, entries *uint32, total *uint32) error {
	s, err := windows.UTF16PtrFromString(server)
	if err != nil {
		return err
	}
	res, _, err := pNetWkstaUserEnum.Call(uintptr(unsafe.Pointer(s)), uintptr(1), uintptr(unsafe.Pointer(bufPtr)), uintptr(maxLen), uintptr(unsafe.Pointer(entries)), uintptr(unsafe.Pointer(total)), uintptr(0))
	if res != 0 {
		return err
	}
	return nil
}

type SHARE_INFO_2 struct {
	NetName           *uint16
	Type              uint32
	Remark            *uint16
	Permissions       uint32
	MaxUses           uint32
	CurrentConections uint32
	Path              *uint16
	Password          *uint16
}

type WKSTA_USER_INFO_1 struct {
	Username    *uint16
	LogonDomain *uint16
	AuthDomains *uint16
	LogonServer *uint16
}

type SERVER_INFO_100 struct {
	Sv100_platform_id uint32
	Sv100_name        *uint16
}

type USER_INFO_1 struct {
	Name        *uint16
	Password    *uint16
	PasswordAge uint32
	Priv        uint32
	HomeDir     *uint16
	Comment     *uint16
	Flags       uint32
	ScriptPath  *uint16
}

type LOCALGROUP_MEMBERS_INFO_3 struct {
	Lgrmi3_domainandname *uint16
}

func NetUserDel(user string) error {
	u, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return err
	}
	res, _, err := pNetUserDel.Call(uintptr(0), uintptr(unsafe.Pointer(u)))
	if res != 0 {
		return fmt.Errorf("Error Code 0x%x", res)
	}
	return nil
}

func NetUserAdd(info *USER_INFO_1) error {
	res, _, _ := pNetUserAdd.Call(uintptr(0), uintptr(1), uintptr(unsafe.Pointer(info)), uintptr(0))
	if res != 0 {
		return fmt.Errorf("Error Code 0x%x", res)
	}
	return nil
}

func NetLocalGroupDelMembers(groupName string, level uint32, buffer *uintptr, entries uint32) error {
	g, err := windows.UTF16PtrFromString(groupName)
	if err != nil {
		return err
	}
	res, _, err := pNetLocalGroupDelMembers.Call(uintptr(0), uintptr(unsafe.Pointer(g)), uintptr(level), uintptr(unsafe.Pointer(buffer)), uintptr(entries))
	if res != 0 {
		return err
	}
	return nil
}

func NetLocalGroupAddMembers(groupName string, level uint32, buffer *uintptr, entries uint32) error {
	g, err := windows.UTF16PtrFromString(groupName)
	if err != nil {
		return err
	}
	res, _, err := pNetLocalGroupAddMembers.Call(uintptr(0), uintptr(unsafe.Pointer(g)), uintptr(level), uintptr(unsafe.Pointer(buffer)), uintptr(entries))
	if res != 0 {
		return err
	}
	return nil
}

func NetApiBufferFree(buffer uintptr) bool {
	res, _, _ := pNetApiBufferFree.Call(buffer)
	if res != 0 {
		return false
	}
	return true
}

func NetApiBufferAllocate(size uint32, buffer uintptr) (uintptr, error) {
	_, _, err := pNetApiBufferAllocate.Call(uintptr(size), buffer)
	if buffer == 0 {
		return 0, err
	}
	return 1, nil
}

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

func NetUserEnum(server string, level uint32, filter uint32, bufPtr **windows.UserInfo10, maxLen int32, entriesRead *uint32, totalEntries *uint32, resumeHandle **uint32) (bool, error) {
	serverNamePtr, err := syscall.UTF16PtrFromString(server)
	if err != nil {
		return false, err
	}
	res, _, err := pNetUserEnum.Call(uintptr(unsafe.Pointer(serverNamePtr)), uintptr(level), uintptr(filter), uintptr(unsafe.Pointer(bufPtr)), uintptr(maxLen), uintptr(unsafe.Pointer(entriesRead)), uintptr(unsafe.Pointer(totalEntries)), uintptr(unsafe.Pointer(resumeHandle)))
	if res != 0 {
		return false, err
	}
	return true, nil
}

func NetServerEnum(level uint32, bufptr *uintptr, prefMaxLen int32, entriesRead *uint32, totalEntries *uint32, serverType uint32, domain string) error {
	Dptr, err := windows.UTF16PtrFromString(domain)
	if err != nil {
		return err
	}
	res, _, _ := pNetServerEnum.Call(uintptr(0), uintptr(level), uintptr(unsafe.Pointer(bufptr)), uintptr(prefMaxLen), uintptr(unsafe.Pointer(entriesRead)), uintptr(unsafe.Pointer(totalEntries)), uintptr(serverType), uintptr(unsafe.Pointer(Dptr)), uintptr(0))
	if res != 0 {
		return fmt.Errorf("NetServerEnum Error %d", res)
	}
	return nil
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
