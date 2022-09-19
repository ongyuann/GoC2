//go:build windows
// +build windows

package listports

import (
	"fmt"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func ListPorts() (string, error) {
	var results string
	var needed uint32
	err := winapi.GetTcpTable2(nil, &needed, true)
	if needed == 0 {
		return "", err
	}
	buffer := make([]byte, needed)
	bufferPtr := (*winapi.MIB_TCPTABLE2)(unsafe.Pointer(&buffer[0]))
	index := int(unsafe.Sizeof(bufferPtr.DwNumEntries))
	step := int(unsafe.Sizeof(bufferPtr.Table))
	err = winapi.GetTcpTable2(bufferPtr, &needed, true)
	if err != nil {
		return "", err
	}
	for x := 0; x < int(bufferPtr.DwNumEntries); x++ {
		t := (*winapi.MIB_TCPROW2)(unsafe.Pointer(&buffer[index]))
		s := winapi.MIB_TCP_STATE(t.DwState)
		handle, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, t.DwOwningPid)
		if err != nil {
			results += fmt.Sprintf("EXE %s PID: %d STATE: %s LADDR: %s LPORT: %d RADDR: %s RPORT: %d\n", "C:\\\\?", t.DwOwningPid, winapi.TCPStatuses[s], winapi.ParseIPv4(t.DwLocalAddr), winapi.DecodePort(t.DwLocalPort), winapi.ParseIPv4(t.DwRemoteAddr), winapi.DecodePort(t.DwRemotePort))
		} else {
			buffer := make([]uint16, 257)
			err := windows.GetModuleFileNameEx(handle, 0, &buffer[0], 256)
			if err != nil {
				results += fmt.Sprintf("EXE %s PID: %d STATE: %s LADDR: %s LPORT: %d RADDR: %s RPORT: %d\n", "C:\\\\?", t.DwOwningPid, winapi.TCPStatuses[s], winapi.ParseIPv4(t.DwLocalAddr), winapi.DecodePort(t.DwLocalPort), winapi.ParseIPv4(t.DwRemoteAddr), winapi.DecodePort(t.DwRemotePort))
			} else {
				exeName := windows.UTF16PtrToString(&buffer[0])
				results += fmt.Sprintf("EXE %s PID: %d STATE: %s LADDR: %s LPORT: %d RADDR: %s RPORT: %d\n", exeName, t.DwOwningPid, winapi.TCPStatuses[s], winapi.ParseIPv4(t.DwLocalAddr), winapi.DecodePort(t.DwLocalPort), winapi.ParseIPv4(t.DwRemoteAddr), winapi.DecodePort(t.DwRemotePort))
			}
		}
		index += step
	}
	return results, nil
}
