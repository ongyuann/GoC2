package winapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pModSecur32Dll             = syscall.NewLazyDLL("Secur32.dll")
	pLsaEnumerateLogonSessions = pModSecur32Dll.NewProc("LsaEnumerateLogonSessions")
	pLsaGetLogonSessionData    = pModSecur32Dll.NewProc("LsaGetLogonSessionData")
	pLsaFreeReturnBuffer       = pModSecur32Dll.NewProc("LsaFreeReturnBuffer")
)

func LsaEnumerateLogonSessions(logonSessionCount *uint64, logonSessionList **windows.LUID) error {
	res, _, err := pLsaEnumerateLogonSessions.Call(uintptr(unsafe.Pointer(logonSessionCount)), uintptr(unsafe.Pointer(logonSessionList)))
	if res != uintptr(windows.STATUS_SUCCESS) {
		return err
	}
	return nil
}

func LsaGetLogonSessionData(logonId *windows.LUID, ppLogonSessionData **SECURITY_LOGON_SESSION_DATA) uintptr {
	res, _, _ := pLsaGetLogonSessionData.Call(uintptr(unsafe.Pointer(logonId)), uintptr(unsafe.Pointer(ppLogonSessionData)))
	if res != uintptr(windows.STATUS_SUCCESS) {
		return res
	}
	return 0
}

func LsaFreeReturnBuffer(buffer uintptr) {
	pLsaFreeReturnBuffer.Call(buffer)
}

type LSA_UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        uintptr
}
type LSA_LAST_INTER_LOGON_INFO struct {
	LastSuccessfulLogon                        uint64
	LastFailedLogon                            uint64
	FailedAttemptCountSinceLastSuccessfulLogon uint32
}

type LUID struct {
	lowPart  uint32
	highPart int32
}
type SECURITY_LOGON_SESSION_DATA struct {
	Size                  uint32
	LogonId               LUID
	UserName              LSA_UNICODE_STRING
	LogonDomain           LSA_UNICODE_STRING
	AuthenticationPackage LSA_UNICODE_STRING
	LogonType             uint32
	Session               uint32
	Sid                   *windows.SID
	LogonTime             int64
	LogonServer           LSA_UNICODE_STRING
	DnsDomainName         LSA_UNICODE_STRING
	Upn                   LSA_UNICODE_STRING
	UserFlags             uint32
	LastLogonInfo         LSA_LAST_INTER_LOGON_INFO
	LogonScript           LSA_UNICODE_STRING
	ProfilePath           LSA_UNICODE_STRING
	HomeDirectory         LSA_UNICODE_STRING
	HomeDirectoryDrive    LSA_UNICODE_STRING
	LogoffTime            uint64
	KickOffTime           uint64
	PasswordLastSet       uint64
	PasswordCanChange     uint64
	PasswordMustChange    uint64
}
