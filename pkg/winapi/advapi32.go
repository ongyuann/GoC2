package winapi

import (
	"os"
	"runtime"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pModAdvapi32             = syscall.NewLazyDLL("advapi32.dll")
	pDuplicateToken          = pModAdvapi32.NewProc("DuplicateToken")
	pCreateProcessWithLogonW = pModAdvapi32.NewProc("CreateProcessWithLogonW")
	pOpenEventLogW           = pModAdvapi32.NewProc("OpenEventLogW")
	pClearEventLogW          = pModAdvapi32.NewProc("ClearEventLogW")
	pCloseEventLog           = pModAdvapi32.NewProc("CloseEventLog")
	pImpersonateLoggedOnUser = pModAdvapi32.NewProc("ImpersonateLoggedOnUser")
	pLogonUser               = pModAdvapi32.NewProc("LogonUserW")
	pCreateProcessWithToken  = pModAdvapi32.NewProc("CreateProcessWithTokenW")
	pGetTokenInformation     = pModAdvapi32.NewProc("GetTokenInformation")
	pLookupAccountSid        = pModAdvapi32.NewProc("LookupAccountSidA")
)

const (
	// Use only network credentials for login
	LOGON_NETCREDENTIALS_ONLY uint32 = 0x00000002
	// The new process does not inherit the error mode of the calling process.
	// Instead, CreateProcessWithLogonW gives the new process the current
	// default error mode.
	CREATE_DEFAULT_ERROR_MODE uint32 = 0x04000000
	// Flag parameter that indicates to use the value set in ShowWindow
	STARTF_USESHOWWINDOW = 0x00000001
	// Tell windows not to show the window
	ShowWindow = 0
)

func ListToEnvironmentBlock(list *[]string) *uint16 {
	if list == nil {
		return nil
	}

	size := 1
	for _, v := range *list {
		size += len(syscall.StringToUTF16(v))
	}

	result := make([]uint16, size)

	tail := 0

	for _, v := range *list {
		uline := syscall.StringToUTF16(v)
		copy(result[tail:], uline)
		tail += len(uline)
	}

	result[tail] = 0

	return &result[0]
}

func ImpersonateLoggedOnUser(token windows.Token) (bool, error) {
	worked, _, err := pImpersonateLoggedOnUser.Call(uintptr(token))
	if worked == 0 {
		return false, err
	}
	return true, nil
}

func CreateProcessWithLogonW(
	username *uint16,
	domain *uint16,
	password *uint16,
	logonFlags uint32,
	applicationName *uint16,
	commandLine *uint16,
	creationFlags uint32,
	environment *uint16,
	currentDirectory *uint16,
	startupInfo *syscall.StartupInfo,
	processInformation *syscall.ProcessInformation) error {
	r1, _, e1 := pCreateProcessWithLogonW.Call(
		uintptr(unsafe.Pointer(username)),
		uintptr(unsafe.Pointer(domain)),
		uintptr(unsafe.Pointer(password)),
		uintptr(logonFlags),
		uintptr(unsafe.Pointer(applicationName)),
		uintptr(unsafe.Pointer(commandLine)),
		uintptr(creationFlags),
		uintptr(unsafe.Pointer(environment)), // env
		uintptr(unsafe.Pointer(currentDirectory)),
		uintptr(unsafe.Pointer(startupInfo)),
		uintptr(unsafe.Pointer(processInformation)))
	runtime.KeepAlive(username)
	runtime.KeepAlive(domain)
	runtime.KeepAlive(password)
	runtime.KeepAlive(applicationName)
	runtime.KeepAlive(commandLine)
	runtime.KeepAlive(environment)
	runtime.KeepAlive(currentDirectory)
	runtime.KeepAlive(startupInfo)
	runtime.KeepAlive(processInformation)
	if int(r1) == 0 {
		return os.NewSyscallError("CreateProcessWithLogonW", e1)
	}
	return nil
}

func CreateProcessWithTokenW(hToken syscall.Handle, dwLogonFlags uint32, applicationName string, commandLine string, dwCreationFlags uint32, lpEnvironment uintptr, currentDirectory string, si *windows.StartupInfo, pi *windows.ProcessInformation) (bool, error) {
	binaryName, err := syscall.UTF16PtrFromString(applicationName)
	if err != nil {
		return false, err
	}
	cmdLine, err := syscall.UTF16PtrFromString(commandLine)
	if err != nil {
		return false, err
	}
	dir, err := syscall.UTF16PtrFromString(currentDirectory)
	if err != nil {
		return false, err
	}
	res, _, err := pCreateProcessWithToken.Call(uintptr(hToken), uintptr(dwLogonFlags), uintptr(unsafe.Pointer(binaryName)), uintptr(unsafe.Pointer(cmdLine)), uintptr(dwCreationFlags), lpEnvironment, uintptr(unsafe.Pointer(dir)), uintptr(unsafe.Pointer(si)), uintptr(unsafe.Pointer(pi)))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func LogonUser(user string, domain string, password string, logonType uint32, logonProvider uint32, hToken *syscall.Handle) (bool, error) {
	userPtr := syscall.StringToUTF16Ptr(user)
	domainPtr := syscall.StringToUTF16Ptr(domain)
	passPtr := syscall.StringToUTF16Ptr(password)
	res, _, err := pLogonUser.Call(uintptr(unsafe.Pointer(userPtr)), uintptr(unsafe.Pointer(domainPtr)), uintptr(unsafe.Pointer(passPtr)), uintptr(logonType), uintptr(logonProvider), uintptr(unsafe.Pointer(hToken)))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func DuplicateToken(existingTokenHandle syscall.Handle, securityImpersonationLevel uint32, duplicatedTokenHandle *syscall.Handle) (bool, error) {
	worked, _, err := pDuplicateToken.Call(uintptr(existingTokenHandle), uintptr(securityImpersonationLevel), uintptr(unsafe.Pointer(duplicatedTokenHandle)))
	if worked == 0 {
		return false, err
	}
	return true, nil
}

func OpenEventLogW(serverName, logSourceName string) (syscall.Handle, error) {
	serverPtr := syscall.StringToUTF16Ptr(serverName)
	logPtr := syscall.StringToUTF16Ptr(logSourceName)
	l, _, err := pOpenEventLogW.Call(uintptr(unsafe.Pointer(serverPtr)), uintptr(unsafe.Pointer(logPtr)))
	if l == 0 {
		return 0, err
	}
	return syscall.Handle(l), nil
}

func CloseEventLog(hEventLog syscall.Handle) (bool, error) {
	res, _, err := pCloseEventLog.Call(uintptr(hEventLog))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func ClearEventLogW(hEventLog syscall.Handle, lpBackupFileName string) (bool, error) {
	if lpBackupFileName == "" {
		res, _, err := pClearEventLogW.Call(uintptr(hEventLog), uintptr(NullRef))
		if res == 0 {
			return false, err
		}
		return true, nil
	}
	backupfilenamePtr := syscall.StringToUTF16Ptr(lpBackupFileName)
	res, _, err := pClearEventLogW.Call(uintptr(hEventLog), uintptr(unsafe.Pointer(backupfilenamePtr)))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func GetTokenIntegrityLevel(hToken syscall.Handle, tokenInformationClass uint32, tokenInformation *windows.Tokenmandatorylabel, tokenInformationlength uint32, returnLength *uint32) (bool, error) {
	res, _, err := pGetTokenInformation.Call(uintptr(hToken), uintptr(tokenInformationClass), uintptr(unsafe.Pointer(tokenInformation)), 28, uintptr(unsafe.Pointer(returnLength)))
	if res == 0 {
		return false, err
	}
	return true, nil
}

//^
//|
//|
//|
/*
func GetTokenInformation(hToken syscall.Handle, tokenInformationClass uint32, tokenInformation uintptr, tokenInformationlength uint32, returnLength *uint32) (bool, error) {
	res, _, err := pGetTokenInformation.Call(uintptr(hToken), uintptr(tokenInformationClass), tokenInformation, 28, uintptr(unsafe.Pointer(returnLength)))
	if res == 0 {
		return false, err
	}
	return true, nil
}
*/
