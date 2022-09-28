package enumrwxmemory

import (
	"fmt"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func ShowCaves(memBuffer []byte, regionSize uintptr, baseAddress uintptr) string {
	var start int
	var inEmpty bool
	var end int
	var x int
	var results string
	for ; x < int(regionSize); x++ {
		if memBuffer[x] == 0 && !inEmpty {
			inEmpty = true
			start = x
		}
		if memBuffer[x] != 0 && inEmpty {
			inEmpty = false
			end = x
			if (end - start) > 1000 { // show only things greater than 1kb
				results += fmt.Sprintf("\t\t %p %p %d bytes\n", unsafe.Pointer(baseAddress+uintptr(start)), unsafe.Pointer(baseAddress+uintptr(end)), end-start)
			}
			start = 0
			end = 0
			continue
		}
	}
	end = x
	if (end - start) > 1000 { // show only things greater than 1kb
		results += fmt.Sprintf("\t\t %p %p %d bytes\n", unsafe.Pointer(baseAddress+uintptr(start)), unsafe.Pointer(baseAddress+uintptr(end)), end-start)
	}
	return results
}

func EnumMemory() (string, error) {
	var results string
	hSnaphshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return "", err
	}
	procEntry := windows.ProcessEntry32{}
	procEntry.Size = uint32(unsafe.Sizeof(procEntry))
	mbi := windows.MemoryBasicInformation{}
	var offset uintptr
	err = windows.Process32First(hSnaphshot, &procEntry)
	if err != nil {
		return "", err

	}
	for {
		err = windows.Process32Next(hSnaphshot, &procEntry)
		if err != nil {
			break
		}
		hProcess, err := windows.OpenProcess(windows.MAXIMUM_ALLOWED, false, procEntry.ProcessID)
		if err != nil {
			continue
		}
		var dotnetloaded string = ""
		ok, _ := winapi.CheckIfDotnetDllLoaded(procEntry.ProcessID)
		if ok {
			dotnetloaded = "DOTNET: LOADED"
		}
		exeName := windows.UTF16PtrToString(&procEntry.ExeFile[0])
		results += fmt.Sprintf("PID: %d EXE: %s %s\n", procEntry.ProcessID, exeName, dotnetloaded)
		for {
			err = windows.VirtualQueryEx(hProcess, offset, &mbi, unsafe.Sizeof(mbi))
			if err != nil {
				break
			}
			offset = uintptr(unsafe.Pointer(mbi.BaseAddress + mbi.RegionSize))
			if mbi.Protect&windows.PAGE_EXECUTE_READWRITE == 0 {
				continue
			}
			if mbi.Protect&0x40 == 0 {
				continue
			}
			if mbi.State&windows.MEM_COMMIT == 0 {
				continue
			}
			if mbi.Type&0x20000 == 0 {
				continue
			}
			buffer := make([]byte, mbi.RegionSize)
			var read uintptr
			err = windows.ReadProcessMemory(hProcess, mbi.BaseAddress, &buffer[0], mbi.RegionSize, &read)
			if err != nil {
				buffer = nil
				continue
			}
			results += fmt.Sprintf("\tRWX: 0x%p Region Sz: %d\n", unsafe.Pointer(mbi.BaseAddress), mbi.RegionSize)
			results += ShowCaves(buffer, mbi.RegionSize, mbi.BaseAddress)
			buffer = nil
		}
		windows.CloseHandle(hProcess)
		offset = 0
	}
	windows.CloseHandle(hSnaphshot)
	return results, nil
}
