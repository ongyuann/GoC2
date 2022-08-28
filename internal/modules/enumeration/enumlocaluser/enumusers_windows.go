//go:build windows
// +build windows

package enumlocaluser

import (
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

// domain api -> https://docs.microsoft.com/en-us/windows/win32/api/lmaccess/nf-lmaccess-netquerydisplayinformation

type LocalGroup0 struct {
	name *uint16
}

type GroupUsers0 struct {
	name *uint16
}

func EnumDomain() (string, error) {
	results := "--- Domain ---\n"
	var nameBuffer *uint16
	var bufType uint32
	err := windows.NetGetJoinInformation(nil, &nameBuffer, &bufType)
	if err != nil {
		return "", err
	}
	results += "- " + windows.UTF16PtrToString(nameBuffer) + "\n"
	return results, nil
}

func EnumGroupsFromUser(username string) (string, error) {
	results := ""
	var count uint32
	var entries uint32
	const maxgroupsmembers = 25
	buffer := &[maxgroupsmembers]LocalGroup0{}
	res, err := winapi.NetUserGetLocalGroups("", username, 0, 0, uintptr(unsafe.Pointer(&buffer)), winapi.MAX_PREFFERED_LENGTH, &count, &entries)
	if !res {
		winapi.NetApiBufferFree(uintptr(unsafe.Pointer(buffer)))
		return "", err
	}
	for x := 0; x < int(count); x++ {
		results += "* " + windows.UTF16PtrToString(buffer[x].name) + "\n"
	}
	winapi.NetApiBufferFree(uintptr(unsafe.Pointer(buffer)))
	return results, nil
}

func EnumGroups() (string, error) {
	// get up to 50 groups
	results := "--- Groups --- \n"
	const maxgroups = 50
	var count uint32
	var resumeHandle *uint32
	const maxgroupsmembers = 50
	buffer := &[maxgroups]LocalGroup0{}
	var entries uint32
	res, err := winapi.NetLocalGroupEnum("", 0, uintptr(unsafe.Pointer(&buffer)), winapi.MAX_PREFFERED_LENGTH, &count, &entries, &resumeHandle)
	if !res {
		winapi.NetApiBufferFree(uintptr(unsafe.Pointer(buffer)))
		return "", err
	}
	for x := 0; x < int(count); x++ {
		results += "- " + windows.UTF16PtrToString(buffer[x].name)
		results += "\n"
	}
	winapi.NetApiBufferFree(uintptr(unsafe.Pointer(buffer)))
	return results, nil
}

func EnumUsers() (string, error) {
	// get up to 50 usernames
	results := "--- Users --- \n"
	buffer := &[50]windows.UserInfo10{}
	var resumeHandle *uint32
	var count uint32
	var entries uint32
	res, err := winapi.NetUserEnum("", 10, 0, uintptr(unsafe.Pointer(&buffer)), winapi.MAX_PREFFERED_LENGTH, &count, &entries, &resumeHandle)
	if !res {
		return "", err
	}
	for x := 0; x < int(count); x++ {
		username := windows.UTF16PtrToString(buffer[x].Name)
		results += "- " + username
		results += "\n"
		groups, _ := EnumGroupsFromUser(username)
		results += groups
		results += "\n"
	}
	// free buffer
	winapi.NetApiBufferFree(uintptr(unsafe.Pointer(buffer)))
	return results, nil
}
