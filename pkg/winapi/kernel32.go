package winapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	HEAP_ZERO_MEMORY           = 0x00000008
	HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
	MEM_DECOMMIT               = 0x00004000
	MEM_RESET                  = 0x00080000
	MEM_TOP_DOWN               = 0x00100000
	MEM_WRITE_WATCH            = 0x00200000
	MEM_PHYSICAL               = 0x00400000
	MEM_RESET_UNDO             = 0x01000000
	MEM_LARGE_PAGES            = 0x20000000
	PAGE_TARGETS_INVALID       = 0x40000000
	PAGE_TARGETS_NO_UPDATE     = 0x40000000

	QUOTA_LIMITS_HARDWS_MIN_DISABLE = 0x00000002
	QUOTA_LIMITS_HARDWS_MIN_ENABLE  = 0x00000001
	QUOTA_LIMITS_HARDWS_MAX_DISABLE = 0x00000008
	QUOTA_LIMITS_HARDWS_MAX_ENABLE  = 0x00000004
)

var (
	pModKernel32          = syscall.NewLazyDLL("kernel32.dll")
	pAllocConsole         = pModKernel32.NewProc("AllocConsole")
	pGetConsoleWindow     = pModKernel32.NewProc("GetConsoleWindow")
	pGetModuleHandleW     = pModKernel32.NewProc("GetModuleHandleW")
	pGetCurrentProcess    = pModKernel32.NewProc("GetCurrentProcess")
	pOpenProcess          = pModKernel32.NewProc("OpenProcess")
	pGetProcessHeap       = pModKernel32.NewProc("GetProcessHeap")
	pHeapCreate           = pModKernel32.NewProc("HeapCreate")
	pCreateProcess        = pModKernel32.NewProc("CreateProcess")
	pGetExitCodeThread    = pModKernel32.NewProc("GetExitCodeThread")
	pVirtualProtect       = pModKernel32.NewProc("VirtualProtect")
	pVirtualProtectEx     = pModKernel32.NewProc("VirtualProtectEx")
	pVirtualFreeEx        = pModKernel32.NewProc("VirtualFreeEx")
	pVirtualFree          = pModKernel32.NewProc("VirtualFree")
	pReadFile             = pModKernel32.NewProc("ReadFile")
	pHeapAlloc            = pModKernel32.NewProc("HeapAlloc")
	pHeapReAlloc          = pModKernel32.NewProc("HeapReAlloc")
	pHeapFree             = pModKernel32.NewProc("HeapFree")
	pHeapDestroy          = pModKernel32.NewProc("HeapDestroy")
	pVirtualAlloc         = pModKernel32.NewProc("VirtualAlloc")
	pVirtualAllocEx       = pModKernel32.NewProc("VirtualAllocEx")
	pWriteProcessMemory   = pModKernel32.NewProc("WriteProcessMemory")
	pReadProcessMemory    = pModKernel32.NewProc("ReadProcessMemory")
	pCreateThread         = pModKernel32.NewProc("CreateThread")
	pCreateRemoteThread   = pModKernel32.NewProc("CreateRemoteThread")
	pWriteFile            = pModKernel32.NewProc("WriteFile")
	pWaitNamedPipe        = pModKernel32.NewProc("WaitNamedPipeW")
	pCreateFile           = pModKernel32.NewProc("CreateFileW")
	pFlushFileBuffers     = pModKernel32.NewProc("FlushFileBuffers")
	PGlobalLock           = pModKernel32.NewProc("GlobalLock")
	PGlobalUnlock         = pModKernel32.NewProc("GlobalUnlock")
	pIsBadReadPtr         = pModKernel32.NewProc("IsBadReadPtr")
	pCreatePipe           = pModKernel32.NewProc("CreatePipe")
	pSetStdHandle         = pModKernel32.NewProc("SetStdHandle")
	pGetProcAddress       = pModKernel32.NewProc("GetProcAddress")
	pCreateEventW         = pModKernel32.NewProc("CreateEventW")
	pSetEvent             = pModKernel32.NewProc("SetEvent")
	pGetThreadContext     = pModKernel32.NewProc("GetThreadContext")
	pSetThreadContext     = pModKernel32.NewProc("SetThreadContext")
	pExitThread           = pModKernel32.NewProc("ExitThread")
	pOpenThread           = pModKernel32.NewProc("OpenThread")
	pGetFileType          = pModKernel32.NewProc("GetFileType")
	pGetProcessIdOfThread = pModKernel32.NewProc("GetProcessIdOfThread")
	pPeekNamedPipe        = pModKernel32.NewProc("PeekNamedPipe")
	pAttachConsole        = pModKernel32.NewProc("AttachConsole")
)

func AttachConsole(pid uint32) error {
	ok, _, err := pAttachConsole.Call(uintptr(pid))
	if ok == 0 {
		return err
	}
	return nil
}

func AllocConsole() (uintptr, error) {
	b, _, err := pAllocConsole.Call()
	return b, err
}
func GetConsoleWindow() uintptr {
	r, _, _ := pGetConsoleWindow.Call()
	return r
}

func PeekNamedPipe(hPipe uintptr, lpBuffer *uintptr, bufferSz uint32, lpBytesRead *uint32, lpTotalBytesAvail *uint32, lpBytesLeft *uint32) (bool, error) {
	b, _, err := pPeekNamedPipe.Call(hPipe, uintptr(unsafe.Pointer(lpBuffer)), uintptr(bufferSz), uintptr(unsafe.Pointer(lpBytesRead)), uintptr(unsafe.Pointer(lpTotalBytesAvail)), uintptr(unsafe.Pointer(lpBytesLeft)))
	if b == 0 {
		return false, err
	}
	return true, nil

}

func GetProcessIdOfThread(handle uintptr) uint32 {
	res, _, _ := pGetProcessIdOfThread.Call(handle)
	return uint32(res)
}
func GetFileType(handle uintptr) uint32 {
	res, _, _ := pGetFileType.Call(handle)
	return uint32(res)
}
func OpenThread(dwDesiredAccess uint32, inheritHandle uint32, threadId uint32) uintptr {
	res, _, _ := pOpenThread.Call(uintptr(dwDesiredAccess), uintptr(inheritHandle), uintptr(threadId))
	if res == 0 {
		return 0
	}
	return res
}

func ExitThread() {
	pExitThread.Call(uintptr(0))
}

func SetThreadContext(handle uintptr, context *CONTEXT) error {
	res, _, err := pSetThreadContext.Call(handle, uintptr(unsafe.Pointer(context)))
	if res == 0 {
		return err
	}
	return nil
}

func GetThreadContext(handle uintptr, context *CONTEXT) error {
	res, _, err := pGetThreadContext.Call(handle, uintptr(unsafe.Pointer(context)))
	if res == 0 {
		return err
	}
	return nil
}

func SetEvent(handle uintptr) error {
	res, _, err := pSetEvent.Call(handle)
	if res == 0 {
		return err
	}
	return nil
}

func CreateEventW(lpSecAttr *windows.SecurityAttributes, bManualReset uint32, bInitialState uint32, name string) (uintptr, error) {
	n, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return 0, err
	}
	res, _, err := pCreateEventW.Call(uintptr(unsafe.Pointer(lpSecAttr)), uintptr(bManualReset), uintptr(bInitialState), uintptr(unsafe.Pointer(n)))
	if res == 0 {
		return 0, err
	}
	return res, nil
}

func GetProcAddress(hModule uintptr, lpProcName *uint16) (uintptr, error) {
	res, _, err := pGetProcAddress.Call(hModule, uintptr(unsafe.Pointer(lpProcName)))
	if res == 0 {
		return 0, err
	}
	return res, nil
}

func HeapDestroy(hHeap uintptr) error {
	res, _, err := pHeapDestroy.Call(hHeap)
	if res == 0 {
		return err
	}
	return nil
}

func HeapFree(hHeap uintptr, flags uint32, lpMem uintptr) error {
	res, _, err := pHeapFree.Call(hHeap, uintptr(flags), lpMem)
	if res == 0 {
		return err
	}
	return nil
}

func VirtualFree(address uintptr, dwSize uint32, dwFreeType uint32) (bool, error) {
	res, _, err := pVirtualFree.Call(address, uintptr(dwSize), uintptr(dwFreeType))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func VirtualFreeEx(hProcess windows.Handle, address uintptr, dwSize uint32, dwFreeType uint32) (bool, error) {
	res, _, err := pVirtualFreeEx.Call(uintptr(hProcess), address, uintptr(dwSize), uintptr(dwFreeType))
	if res == 0 {
		return false, err
	}
	return true, nil
}

func VirtualAlloc(lpAddress uintptr, dwSize uint32, allocationType uint32, flProtect uint32) (uintptr, error) {
	lpBaseAddress, _, err := pVirtualAlloc.Call(
		lpAddress,
		uintptr(dwSize),
		uintptr(allocationType),
		uintptr(flProtect))
	if lpBaseAddress == 0 {
		return 0, err
	}
	return lpBaseAddress, nil
}

func SetStdHandle(nStdHandle uint32, nHandle windows.Handle) error {
	r, _, err := pSetStdHandle.Call(uintptr(nStdHandle), uintptr(nHandle))
	if r == 0 {
		return err
	}
	return nil
}

func CreatePipe(hReadPipe uintptr, hWritePipe uintptr, lpPipeAttributes uintptr, nSize uint32) error {
	r, _, err := pCreatePipe.Call(uintptr(unsafe.Pointer(&hReadPipe)), uintptr(unsafe.Pointer(&hWritePipe)), lpPipeAttributes, uintptr(nSize))
	if r == 0 {
		return err
	}
	return nil
}

func IsBadReadPtr(startAddr uintptr, blockSz uintptr) bool {
	res, _, _ := pIsBadReadPtr.Call(startAddr, blockSz)
	if res == 0 {
		return true
	}
	return false
}

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

func HeapCreate(flOptions uint32, dwInitialSz uint32, dwMaximumSz uint32) (uintptr, error) {
	heap, _, err := pHeapCreate.Call(uintptr(flOptions), uintptr(dwInitialSz), 0)
	if heap == 0 {
		return 0, err
	}
	return heap, nil
}

func HeapReAlloc(hHeap syscall.Handle, dwFlags uint32, lpMem uintptr, dwBytes uint32) (uintptr, error) {
	res, _, err := pHeapReAlloc.Call(uintptr(hHeap), uintptr(dwFlags), lpMem, uintptr(dwBytes))
	if res == 0 {
		return 0, err
	}
	return res, nil
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

func ReadFile(handle syscall.Handle, lpBuffer uintptr, bytesToRead uint32, numberOfBytesRead *uint32, lpOverlapped uintptr) (bool, error) {
	result, _, err := pWriteFile.Call(uintptr(handle), lpBuffer, uintptr(bytesToRead), uintptr(unsafe.Pointer(numberOfBytesRead)), lpOverlapped)
	if result == 0 {
		return false, err
	}
	return true, nil
}

func WriteFile(handle syscall.Handle, lpBuffer uintptr, bytesToWrite uint32, numberOfBytesWritten *uint32, lpOverlapped uintptr) bool {
	result, _, _ := pWriteFile.Call(uintptr(handle), lpBuffer, uintptr(bytesToWrite), uintptr(unsafe.Pointer(numberOfBytesWritten)), lpOverlapped)
	if result == 0 {
		return false
	}
	return true
}

func CreateFile(lpFileName string, desiredAccess uint32, dwShareMode uint32, lpSecuityAttributes uintptr, dwCreationDisposition uint32, dwFlags uint32, hTemplateFile uintptr) uintptr {
	lpFileNamePtr, err := syscall.UTF16PtrFromString(lpFileName)
	if err != nil {
		return 0
	}
	handle, _, _ := pCreateFile.Call(uintptr(unsafe.Pointer(lpFileNamePtr)), uintptr(desiredAccess), uintptr(dwShareMode), lpSecuityAttributes, uintptr(dwCreationDisposition), uintptr(dwFlags), hTemplateFile)
	if handle == 0 {
		return 0
	}
	return handle
}

func WaitNamedPipe(pipeName string, timout uint32) int {
	ptr, err := syscall.UTF16PtrFromString(pipeName)
	if err != nil {
		return 0
	}
	_, _, _ = pWaitNamedPipe.Call(uintptr(unsafe.Pointer(ptr)), uintptr(timout))
	return 1
}

func FlushFileBuffers(handle syscall.Handle) bool {
	res, _, _ := pFlushFileBuffers.Call(uintptr(handle))
	return res != 0
}
