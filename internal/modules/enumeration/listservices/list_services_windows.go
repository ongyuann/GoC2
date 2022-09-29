//go:build windows
// +build windows

package listservices

import (
	"encoding/json"
	"fmt"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

func ListServices() (string, error) {
	var s *uint16
	//var resultsString string
	var resultsString strings.Builder
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
	var data []byte
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
		//resultsString += fmt.Sprintf("NAME: %s\n", name)
		resultsString.WriteString(fmt.Sprintf("NAME: %s\n", name))
		data, err = json.MarshalIndent(serviceConfig, "", " ")
		if err != nil {
			serv.Close()
			continue
		}
		//resultsString += fmt.Sprintf(string(data))
		resultsString.WriteString(string(data))
	}
	svcMgr.Disconnect()
	//return resultsString, nil
	return resultsString.String(), nil
}
