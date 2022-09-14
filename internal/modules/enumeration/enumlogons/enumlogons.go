package enumlogons

import (
	"fmt"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

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
