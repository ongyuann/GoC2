package winapi

import "syscall"

var (
	pModDbgHelp32      = syscall.NewLazyDLL("Dbghelp.dll")
	pMiniDumpWriteDump = pModDbgHelp32.NewProc("MiniDumpWriteDump")
)

const (
	PROCESS_ALL_ACCESS     = 0x001F0FFF
	MiniDumpWithFullMemory = 0x00000002
)

func MinidumpWriteDump(hProcess syscall.Handle, processId uint32, hFile syscall.Handle, dumpType uint32, exceptionParam uintptr, streamParam uintptr, callbackParam uintptr) (bool, error) {
	r, _, err := pMiniDumpWriteDump.Call(uintptr(hProcess), uintptr(processId), uintptr(hFile), uintptr(dumpType), exceptionParam, streamParam, callbackParam)
	if r == 0 {
		return false, err
	}
	return true, nil
}
