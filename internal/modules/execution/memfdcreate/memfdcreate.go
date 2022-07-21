//go:build linux
// +build linux

package memfdcreate

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

func MemfdCreate(data []byte, fakeFileName string) (string, error) {
	fd, err := unix.MemfdCreate(fakeFileName, 0)
	if err != nil {
		return "", err
	}
	err = unix.Ftruncate(fd, int64(len(data)))
	if err != nil {
		return "", err
	}
	mappedData, err := unix.Mmap(fd, 0, len(data), unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC|unix.MFD_CLOEXEC, unix.MAP_SHARED)
	if err != nil {
		return "", err
	}
	copy(mappedData, data)
	fname := fmt.Sprintf("/proc/%d/fd/%d", os.Getpid(), fd)
	var sysProcAttr = syscall.SysProcAttr{Setsid: true}
	var procAttr = syscall.ProcAttr{Sys: &sysProcAttr, Files: []uintptr{0, 1, 2}} //Files: stdin,stderr,stout apply to the same tty than filelessxec
	childPid, err := syscall.ForkExec(fname, []string{fakeFileName}, &procAttr)
	if err != nil {
		return "", err
	}
	unix.Close(fd)
	/* if we wanted to wait.
	if err == nil {
		fmt.Println("Waiting for child to terminate..")
		_, err = syscall.Wait4(childPid,nil,0,nil)
	}
	*/
	return fmt.Sprintf("[+] Executed In Memory Elf Pid: %d\n", childPid), nil
}
