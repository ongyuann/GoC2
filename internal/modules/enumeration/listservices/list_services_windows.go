//go:build windows
// +build windows

package listservices

import (
	"encoding/json"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func ListServices() (string, error) {
	var s *uint16
	var resultsString string
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
		data, err := json.MarshalIndent(serviceConfig, "", " ")
		if err != nil {
			serv.Close()
			continue
		}
		resultsString += string(data)
	}
	svcMgr.Disconnect()
	return resultsString, nil
}
