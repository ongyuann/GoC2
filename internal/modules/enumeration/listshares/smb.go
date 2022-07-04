package listshares

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/hirochachacha/go-smb2"
)

func WriteFileOnShare(args []string) (string, error) {
	if len(args) < 6 {
		return "", errors.New("Not Enough Args.")
	}
	machine := args[0]
	userTmp := args[1]
	userSlice := strings.Split(userTmp, "\\")
	if len(userSlice) < 2 {
		return "", errors.New("User Format Must Be DOMAIN\\User")
	}
	domain := userSlice[0]
	user := userSlice[1]
	pass := args[2]
	shareName := args[3]
	fileToWrite := args[4]
	fileToRead := args[5]
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
				//Password: pass,
				Hash: pass,
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
	share, err := s.Mount(shareName)
	if err != nil {
		return "", err
	}
	defer share.Umount()
	fileData, err := os.ReadFile(fileToRead)
	if err != nil {
		return "", err
	}
	err = share.WriteFile(fileToWrite, fileData, 0644)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Wrote File Contents To %s\\%s", shareName, fileToWrite), nil
}

func ReadFileOnShare(args []string) (string, error) {
	if len(args) < 5 {
		return "", errors.New("Not Enough Args.")
	}
	machine := args[0]
	userTmp := args[1]
	userSlice := strings.Split(userTmp, "\\")
	if len(userSlice) < 2 {
		return "", errors.New("User Format Must Be DOMAIN\\User")
	}
	domain := userSlice[0]
	user := userSlice[1]
	pass := args[2]
	shareName := args[3]
	fileToRead := args[4]
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
				//Password: pass,
				Hash: pass,
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
	share, err := s.Mount(shareName)
	if err != nil {
		return "", err
	}
	defer share.Umount()
	data, err := share.ReadFile(fileToRead)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func DeleteFileOnShare(args []string) (string, error) {
	if len(args) < 5 {
		return "", errors.New("Not Enough Args.")
	}
	machine := args[0]
	userTmp := args[1]
	userSlice := strings.Split(userTmp, "\\")
	if len(userSlice) < 2 {
		return "", errors.New("User Format Must Be DOMAIN\\User")
	}
	domain := userSlice[0]
	user := userSlice[1]
	pass := args[2]
	shareName := args[3]
	fileToDelete := args[4]
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
				//Password: pass,
				Hash: pass,
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
	shr, err := s.Mount(shareName)
	if err != nil {
		return "", err
	}
	shr.Umount()
	err = shr.Remove(fileToDelete)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Deleted %s\\%s", shareName, fileToDelete), nil
}

func ListShares(args []string) (string, error) {
	if len(args) < 3 {
		return "", errors.New("Not Enough Args.")
	}
	machine := args[0]
	userTmp := args[1]
	userSlice := strings.Split(userTmp, "\\")
	if len(userSlice) < 2 {
		return "", errors.New("User Format Must Be DOMAIN\\User")
	}
	domain := userSlice[0]
	user := userSlice[1]
	pass := args[2]
	results := ""
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
				//Password: pass,
				Hash: pass,
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
	names, err := s.ListSharenames()
	if err != nil {
		return "", err
	}

	for _, name := range names {
		results += (name + "\n")
	}
	return results, nil
}
