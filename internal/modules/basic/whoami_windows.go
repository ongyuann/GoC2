//go:build windows
// +build windows

package basic

import (
	"syscall"

	//"github.com/latortuga71/wsC2/pkg/windows"
	"github.com/latortuga71/wsC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func GetIntegrity() string {
	token := windows.GetCurrentProcessToken()
	tml := windows.Tokenmandatorylabel{}
	var realSz uint32
	res, err := winapi.GetTokenIntegrityLevel(syscall.Handle(token), windows.TokenIntegrityLevel, &tml, 28, &realSz)
	if !res {
		return err.Error()
	}
	var r *uint16
	err = windows.ConvertSidToStringSid(tml.Label.Sid, &r)
	if err != nil {
		return err.Error()
	}
	s := windows.UTF16PtrToString(r)
	switch s {
	case "S-1-16-0":
		return "Untrusted"
	case "S-1-16-4096":
		return "Low"
	case "S-1-16-8192":
		return "Medium"
	case "S-1-16-8448":
		return "Medium Plus"
	case "S-1-16-12288":
		return "High"
	case "S-1-16-16384":
		return "System"
	case "S-1-16-20480":
		return "ProtectedProcessMandatory"
	case "S-1-16-28672":
		return "SecureProtectedProcess"
	default:
		return "???"
	}
}

func WhoAmI() (string, error) {
	var bufferSz uint32 = 255
	buffer := make([]uint16, bufferSz)
	err := windows.GetUserNameEx(2, &buffer[0], &bufferSz)
	if err != nil {
		return "", err
	}
	originalUser := windows.UTF16ToString(buffer)
	var sid *windows.SID

	// Although this looks scary, it is directly copied from the
	// official windows documentation. The Go API for this is a
	// direct wrap around the official C++ API.
	// See https://docs.microsoft.com/en-us/windows/desktop/api/securitybaseapi/nf-securitybaseapi-checktokenmembership
	err = windows.AllocateAndInitializeSid(
		&windows.SECURITY_NT_AUTHORITY,
		2,
		windows.SECURITY_BUILTIN_DOMAIN_RID,
		windows.DOMAIN_ALIAS_RID_ADMINS,
		0, 0, 0, 0, 0, 0,
		&sid)
	if err != nil {
		return "", err
	}
	defer windows.FreeSid(sid)
	// This appears to cast a null pointer so I'm not sure why this
	// works, but this guy says it does and it Works for Me™:
	// https://github.com/golang/go/issues/28804#issuecomment-438838144
	//token := windows.Token(0)
	//member, err := token.IsMember(sid)
	//if err != nil {
	//	return "", err
	//}
	return originalUser, nil
}
