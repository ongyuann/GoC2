package loggedonusers

import (
	"fmt"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func EnumLoggedOnUsers(server string) (string, error) {
	var results string = "\n"
	var buffer *winapi.WKSTA_USER_INFO_1 = nil
	var count uint32
	var entries uint32
	err := winapi.NetWkstaUserEnum(server, &buffer, winapi.MAX_PREFFERED_LENGTH, &count, &entries)
	if err != nil {
		return "", err
	}
	var start *winapi.WKSTA_USER_INFO_1 = buffer
	for x := 0; x < int(count); x++ {
		username := windows.UTF16PtrToString(buffer.Username)
		domain := windows.UTF16PtrToString(buffer.LogonDomain)
		serv := windows.UTF16PtrToString(buffer.LogonServer)
		results += fmt.Sprintf("[+] %s\\%s LOGON SERVER: %s\n", domain, username, serv)
		buffer = (*winapi.WKSTA_USER_INFO_1)(unsafe.Pointer(uintptr(unsafe.Pointer(buffer)) + 32)) // size 8 because struct contains 1 pointer
	}
	// free buffer
	winapi.NetApiBufferFree(uintptr(unsafe.Pointer(start)))
	return results, nil
}
