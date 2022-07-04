package winapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	HEAP_ZERO_MEMORY           = 0x00000008
	HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
)

var (
	pModKernel32        = syscall.NewLazyDLL("kernel32.dll")
	pGetCurrentProcess  = pModKernel32.NewProc("GetCurrentProcess")
	pOpenProcess        = pModKernel32.NewProc("OpenProcess")
	pGetProcessHeap     = pModKernel32.NewProc("GetProcessHeap")
	pHeapCreate         = pModKernel32.NewProc("HeapCreate")
	pCreateProcess      = pModKernel32.NewProc("CreateProcess")
	pGetExitCodeThread  = pModKernel32.NewProc("GetExitCodeThread")
	pVirtualProtect     = pModKernel32.NewProc("VirtualProtect")
	pVirtualProtectEx   = pModKernel32.NewProc("VirtualProtectEx")
	pReadFile           = pModKernel32.NewProc("ReadFile")
	pHeapAlloc          = pModKernel32.NewProc("HeapAlloc")
	pHeapFree           = pModKernel32.NewProc("HeapFree")
	pVirtualAlloc       = pModKernel32.NewProc("VirtualAlloc")
	pVirtualAllocEx     = pModKernel32.NewProc("VirtualAllocEx")
	pWriteProcessMemory = pModKernel32.NewProc("WriteProcessMemory")
	pReadProcessMemory  = pModKernel32.NewProc("ReadProcessMemory")
	pCreateThread       = pModKernel32.NewProc("CreateThread")
	pCreateRemoteThread = pModKernel32.NewProc("CreateRemoteThread")
	pWriteFile          = pModKernel32.NewProc("WriteFile")
	pWaitNamedPipe      = pModKernel32.NewProc("WaitNamedPipe")
	pCreateFile         = pModKernel32.NewProc("CreateFile")
	pFlushFileBuffers   = pModKernel32.NewProc("FlushFileBuffers")
)

func GetCurrentProcess() windows.Handle {
	hCurrentProc, _, _ := pGetCurrentProcess.Call()
	return windows.Handle(hCurrentProc)
}

func GetExitCodeThread(hThread syscall.Handle, lpExitCode *uint32) (bool, error) {
	res, _, err := pGetExitCodeThread.Call(uintptr(hThread), uintptr(unsafe.Pointer(lpExitCode)))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func OpenProcess(desiredAccess uint32, inheritHandle uint32, processId uint32) (syscall.Handle, error) {
	procHandle, _, err := pOpenProcess.Call(uintptr(desiredAccess), uintptr(inheritHandle), uintptr(processId))
	if procHandle == 0 {
		return 0, err
	}
	return syscall.Handle(procHandle), nil
}

func CreateRemoteThread(hProcess syscall.Handle, lpThreadAttributes uintptr, dwStackSz uint32, lpStartAddress uintptr, lpParameteter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (syscall.Handle, error) {
	thread, _, err := pCreateRemoteThread.Call(
		uintptr(hProcess),
		lpThreadAttributes,
		uintptr(dwStackSz),
		lpStartAddress,
		lpParameteter,
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(lpThreadId)))
	if thread == 0 {
		return 0, err
	}
	return syscall.Handle(thread), nil
}

func CreateThread(lpThreadAttributes uintptr, dwStackSz uint32, lpStartAddress uintptr, lpParameteter uintptr, dwCreationFlags uint32, lpThreadId *uint32) (syscall.Handle, error) {
	thread, _, err := pCreateThread.Call(
		lpThreadAttributes,
		uintptr(dwStackSz),
		lpStartAddress,
		lpParameteter,
		uintptr(dwCreationFlags),
		uintptr(unsafe.Pointer(lpThreadId)))
	if thread == 0 {
		return 0, err
	}
	return syscall.Handle(thread), nil
}

func WriteProcessMemory(hProcess syscall.Handle, lpAddresss uintptr, lpBuffer uintptr, nSize uint32, lpNumberOfBytesWritten *uint32) (bool, error) {
	writeMem, _, err := pWriteProcessMemory.Call(
		uintptr(hProcess),
		lpAddresss,
		lpBuffer,
		uintptr(nSize),
		uintptr(unsafe.Pointer(lpNumberOfBytesWritten)))
	if writeMem == 0 {
		return false, err
	}
	return true, nil
}

func VirtualAllocEx(hProcess syscall.Handle, lpAddress uintptr, dwSize uint32, allocationType uint32, flProtect uint32) (uintptr, error) {
	lpBaseAddress, _, err := pVirtualAllocEx.Call(
		uintptr(hProcess),
		lpAddress,
		uintptr(dwSize),
		uintptr(allocationType),
		uintptr(flProtect))
	if lpBaseAddress == 0 {
		return 0, err
	}
	return lpBaseAddress, nil
}

func VirtualProtectEx(hProcess syscall.Handle, lpAddress uintptr, dwSize uint32, flNewProtect uint32, lpflOldProtect *uint32) (bool, error) {
	res, _, err := pVirtualProtectEx.Call(uintptr(hProcess), lpAddress, uintptr(dwSize), uintptr(flNewProtect), uintptr(unsafe.Pointer(lpflOldProtect)))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func HeapCreate(flOptions uint32, dwInitialSz uint32, dwMaximumSz uint32) (syscall.Handle, error) {
	heap, _, err := pHeapCreate.Call(uintptr(flOptions), uintptr(dwInitialSz), 0)
	if heap == 0 {
		return 0, err
	}
	return syscall.Handle(heap), nil
}

func HeapAlloc(hHeap syscall.Handle, dwFlags uint32, dwBytes uint32) (uintptr, error) {
	lpAddr, _, err := pHeapAlloc.Call(uintptr(hHeap), uintptr(dwFlags), uintptr(dwBytes))
	if lpAddr == 0 {
		return 0, err
	}
	return lpAddr, nil
}

func ReadProcessMemory(hProcess syscall.Handle, lpBaseAddress uintptr, lpBuffer uintptr, nSize uint32, lpNumberOfBytesRead *uint32) (bool, error) {
	ok, _, err := pReadProcessMemory.Call(
		uintptr(hProcess),
		lpBaseAddress,
		lpBuffer,
		uintptr(nSize),
		uintptr(unsafe.Pointer(lpNumberOfBytesRead)))
	if ok == 0 {
		return false, err
	}
	return true, nil
}
