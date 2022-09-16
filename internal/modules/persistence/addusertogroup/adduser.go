package addusertogroup

import (
	"fmt"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func AddUser(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("Not enough args")
	}
	name := args[0]
	pw := args[1]
	user := winapi.USER_INFO_1{}
	nptr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	pptr, err := windows.UTF16PtrFromString(pw)
	if err != nil {
		return "", err
	}
	user.Name = nptr
	user.Password = pptr
	user.Priv = 1    // USER_PRIV_USER
	user.Flags = 0x1 // UF_SCRIPT
	err = winapi.NetUserAdd(&user)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[+] Successfully added %s", name), nil
}

func RemoveUser(args []string) (string, error) {
	if len(args) == 0 {
		return "", fmt.Errorf("Not Enough Args.")
	}
	name := args[0]
	err := winapi.NetUserDel(name)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[+] Successfully removed %s", name), nil
}

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
