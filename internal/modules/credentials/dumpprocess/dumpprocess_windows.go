//go:build windows
// +build windows

package dumpprocess

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/latortuga71/wsC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func MiniDumpProcess(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args.")
	}
	pid := args[0]
	dumpFilePath := args[1]
	path, err := syscall.UTF16PtrFromString(dumpFilePath)
	if err != nil {
		return "", err
	}
	hFile, err := windows.CreateFile(path, windows.GENERIC_READ|windows.GENERIC_WRITE, 0, nil, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL, windows.Handle(winapi.NullRef))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(hFile)
	intPid, err := strconv.Atoi(pid)
	if err != nil {
		return "", err
	}
	hProc, err := windows.OpenProcess(winapi.PROCESS_ALL_ACCESS, false, uint32(intPid))
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(hProc)
	r, err := winapi.MinidumpWriteDump(syscall.Handle(hProc), uint32(intPid), syscall.Handle(hFile), winapi.MiniDumpWithFullMemory, uintptr(winapi.NullRef), uintptr(winapi.NullRef), uintptr(winapi.NullRef))
	if !r {
		return "", err
	}
	fi, err := os.Stat(dumpFilePath)
	if err != nil {
		return "", err
	}
	size := (fi.Size() / 1048576)
	return fmt.Sprintf("Wrote Dump To %s %d MB", dumpFilePath, size), nil
}
