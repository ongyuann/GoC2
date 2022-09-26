//go:build windows
// +build windows

package enumlocaluser

import (
	"fmt"
	"log"
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

func EnumLocal() string {
	log.Println("ENUM LOCAL CALLED")
	var results string
	domain, err := EnumDomain()
	if err != nil {
		results += domain
	}
	users, err := EnumUsers()
	if err == nil {
		results += users
	}
	groups, err := EnumGroups()
	if err == nil {
		results += groups
	}
	logons, err := EnumLogons()
	if err == nil {
		results += logons
	}
	if results == "" {
		return "Nothing Found."
	}
	return results
}

func EnumLogons() (string, error) {
	var results string
	var logonSessionCount uint64
	var logonSessionList *windows.LUID
	if err := winapi.LsaEnumerateLogonSessions(&logonSessionCount, &logonSessionList); err != nil {
		return "", err
	}
	var logonSessionData *winapi.SECURITY_LOGON_SESSION_DATA
	for x := 0; x < int(logonSessionCount); x++ {
		if code := winapi.LsaGetLogonSessionData(logonSessionList, &logonSessionData); code != uintptr(windows.STATUS_SUCCESS) {
			// Skipping access denied.
			logonSessionList = (*windows.LUID)(unsafe.Pointer(uintptr(unsafe.Pointer(logonSessionList)) + uintptr(8)))
			continue
		}
		name := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(logonSessionData.UserName.Buffer)))
		domain := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(logonSessionData.LogonDomain.Buffer)))
		authType := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(logonSessionData.AuthenticationPackage.Buffer)))
		var logonTypeStr string
		switch logonSessionData.LogonType {
		case 0:
			logonTypeStr = "Undefined"
		case 2:
			logonTypeStr = "Interactive"
		case 3:
			logonTypeStr = "Network"
		case 4:
			logonTypeStr = "Batch"
		case 5:
			logonTypeStr = "Service"
		case 6:
			logonTypeStr = "Proxy"
		case 7:
			logonTypeStr = "Unlock"
		case 8:
			logonTypeStr = "NetworkCleartext"
		case 9:
			logonTypeStr = "NewCredentials"
		case 10:
			logonTypeStr = "RemoteInteractive"
		case 11:
			logonTypeStr = "CachedInteractive"
		default:
			logonTypeStr = "?"
		}
		results += fmt.Sprintf("%s SESSION: %d %s\\%s %s\n", logonTypeStr, logonSessionData.Session, domain, name, authType)
		logonSessionList = (*windows.LUID)(unsafe.Pointer(uintptr(unsafe.Pointer(logonSessionList)) + uintptr(8)))
	}
	winapi.LsaFreeReturnBuffer(uintptr(unsafe.Pointer(&logonSessionList)))
	return results, nil
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
	var buffer *LocalGroup0
	res, err := winapi.NetUserGetLocalGroups("", username, 0, 0, uintptr(unsafe.Pointer(&buffer)), winapi.MAX_PREFFERED_LENGTH, &count, &entries)
	if !res {
		winapi.NetApiBufferFree(uintptr(unsafe.Pointer(buffer)))
		return "", err
	}
	var start *LocalGroup0 = buffer
	for x := 0; x < int(count); x++ {
		results += "* " + windows.UTF16PtrToString(buffer.name) + "\n"
		buffer = (*LocalGroup0)(unsafe.Pointer(uintptr(unsafe.Pointer(buffer)) + 8))
	}
	winapi.NetApiBufferFree(uintptr(unsafe.Pointer(start)))
	return results, nil
}

func EnumGroups() (string, error) {
	results := "--- Groups --- \n"
	const maxgroups = 50
	var count uint32
	var resumeHandle *uint32
	const maxgroupsmembers = 50
	var buffer *LocalGroup0
	var entries uint32
	res, err := winapi.NetLocalGroupEnum("", 0, uintptr(unsafe.Pointer(&buffer)), winapi.MAX_PREFFERED_LENGTH, &count, &entries, &resumeHandle)
	if !res {
		winapi.NetApiBufferFree(uintptr(unsafe.Pointer(buffer)))
		return "", err
	}
	var start *LocalGroup0 = buffer
	for x := 0; x < int(count); x++ {
		results += "- " + windows.UTF16PtrToString(buffer.name)
		results += "\n"
		buffer = (*LocalGroup0)(unsafe.Pointer(uintptr(unsafe.Pointer(buffer)) + 8))
	}
	winapi.NetApiBufferFree(uintptr(unsafe.Pointer(start)))
	return results, nil
}

func EnumUsers() (string, error) {
	results := "--- Users --- \n"
	var buffer *windows.UserInfo10 = nil
	var resumeHandle *uint32
	var count uint32
	var entries uint32
	res, err := winapi.NetUserEnum("", 10, 0, &buffer, winapi.MAX_PREFFERED_LENGTH, &count, &entries, &resumeHandle)
	if !res {
		return "", err
	}
	var start *windows.UserInfo10 = buffer
	for x := 0; x < int(count); x++ {
		log.Printf("%p", buffer)
		username := windows.UTF16PtrToString(buffer.Name)
		results += "- " + username
		results += "\n"
		group, err := EnumGroupsFromUser(username)
		if err == nil {
			results += group
			results += "\n"
		}
		buffer = (*windows.UserInfo10)(unsafe.Pointer(uintptr(unsafe.Pointer(buffer)) + 32))
	}
	// free buffer
	winapi.NetApiBufferFree(uintptr(unsafe.Pointer(start)))
	return results, nil
}

func EnumDomainServers() (string, error) {
	var buffer uintptr
	var count uint32
	var entries uint32
	err := winapi.NetServerEnum(100, &buffer, winapi.MAX_PREFFERED_LENGTH, &count, &entries, 0xFFFFFFFF, "hackerlab")
	if err != nil {
		log.Println(err)
		return "", err
	}
	log.Println(count)
	log.Println(entries)
	for x := 0; x < int(count); x++ {
		serverEntry := (*winapi.SERVER_INFO_100)(unsafe.Pointer(buffer))
		log.Println(windows.UTF16PtrToString(serverEntry.Sv100_name))
		buffer = (buffer + 8) // move pointer over?
	}
	winapi.NetApiBufferFree(buffer)
	return "", nil
}
