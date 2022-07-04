//go:build windows
// +build windows

package services

import (
	"errors"
	"fmt"
	"log"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

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
	log.Println("Connected to remote service")
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
	log.Println("opened service")
	oldBinPath := c.BinaryPathName
	c.BinaryPathName = serviceBinary
	err = s.UpdateConfig(c)
	if err != nil {
		return "", err
	}
	log.Println("Updated config")
	s.Control(svc.Stop)
	log.Println("stopped service")
	time.Sleep(time.Second * 5)
	s.Start()
	time.Sleep(time.Second * 5)
	log.Println("started service")
	c, err = s.Config()
	if err != nil {
		return "", err
	}
	c.BinaryPathName = oldBinPath
	err = s.UpdateConfig(c)
	if err != nil {
		return "", err
	}
	log.Println("checking config")
	return fmt.Sprintf("Should Have Worked"), nil
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
