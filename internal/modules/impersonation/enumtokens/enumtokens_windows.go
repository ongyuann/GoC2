//go:build windows
// +build windows

package enumtokens

import (
	"encoding/json"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Proc struct {
	Name   string
	Pid    uint32
	Owner  string
	Domain string
}

type TOKEN_USER struct {
	User windows.SIDAndAttributes
}

func getLogonFromToken(token *windows.Token) (string, string, error) {
	user, err := token.GetTokenUser()
	if err != nil {
		return "", "", err
	}
	a, d, _, err := user.User.Sid.LookupAccount("")
	if err != nil {
		return "", "", err
	}
	return a, d, nil
}

func checkIfOwnerAlreadyHasProc(o string, owners []string) bool {
	for _, owner := range owners {
		if o == owner {
			return true
		}
	}
	return false
}

func EnumTokens() (string, error) {
	var owners []string
	var procs []Proc
	hSnapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", err
	}
	var pe32 windows.ProcessEntry32
	pe32.Size = uint32(unsafe.Sizeof(pe32))
	err = windows.Process32First(hSnapshot, &pe32)
	if err != nil {
		return "", err
	}
	for {
		err = windows.Process32Next(hSnapshot, &pe32)
		if err != nil {
			break
		}
		var hToken windows.Token
		procHandle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, pe32.ProcessID)
		if err != nil {
			continue
		}
		err = windows.OpenProcessToken(procHandle, windows.TOKEN_QUERY, &hToken)
		if err != nil {
			windows.CloseHandle(procHandle)
			continue
		}
		o, d, err := getLogonFromToken(&hToken)
		if err != nil {
			windows.CloseHandle(windows.Handle(hToken))
			windows.CloseHandle(procHandle)
			continue
		}
		if checkIfOwnerAlreadyHasProc(o, owners) {
			windows.CloseHandle(windows.Handle(hToken))
			windows.CloseHandle(procHandle)
			continue
		}
		owners = append(owners, o)
		p := Proc{
			Name:   syscall.UTF16ToString(pe32.ExeFile[:]),
			Pid:    pe32.ProcessID,
			Owner:  o,
			Domain: d + "\\" + o,
		}
		procs = append(procs, p)
		windows.CloseHandle(windows.Handle(hToken))
		windows.CloseHandle(procHandle)
	}
	windows.CloseHandle(hSnapshot)
	results, err := json.MarshalIndent(procs, "", " ")
	if err != nil {
		return "", err
	}
	return string(results), nil
}
