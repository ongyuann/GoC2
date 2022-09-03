//go:build windows
// +build windows

package listports

import (
	"fmt"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
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
		results += fmt.Sprintf("PID: %d STATE: %s LADDR: %s LPORT: %d RADDR: %s RPORT: %d\n", t.DwOwningPid, winapi.TCPStatuses[s], winapi.ParseIPv4(t.DwLocalAddr), winapi.DecodePort(t.DwLocalPort), winapi.ParseIPv4(t.DwRemoteAddr), winapi.DecodePort(t.DwRemotePort))
		index += step
	}
	return results, nil
}
