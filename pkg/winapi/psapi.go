package winapi

import (
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pPsapi                    = syscall.NewLazyDLL("Psapi.dll")
	pEnumDeviceDrivers        = pPsapi.NewProc("EnumDeviceDrivers")
	pGetDeviceDriverBaseNameW = pPsapi.NewProc("GetDeviceDriverBaseNameW")
	pEnumProcessModules       = pPsapi.NewProc("EnumProcessModules")
	pGetProcessImageFileNameW = pPsapi.NewProc("GetProcessImageFileNameW")
)

func GetProcessImageFileNameW(hproc uintptr, lpImageFileName *uint16, size uint32) uint32 {
	res, _, _ := pGetProcessImageFileNameW.Call(hproc, uintptr(unsafe.Pointer(lpImageFileName)), uintptr(size))
	return uint32(res)
}

func GetModuleList(pid uint32) ([]string, error) {
	mod := make([]string, 0)
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return nil, err
	}
	var n uint32
	var needed uint32
	ret, _, err := pEnumProcessModules.Call(
		uintptr(hProc),
		0,
		uintptr(n),
		uintptr(unsafe.Pointer(&needed)))
	if ret == 0 {
		return nil, err
	}
	if int(ret) == 1 && needed > 0 {
		procHandles := make([]syscall.Handle, needed)
		procHandlesPtr := unsafe.Pointer(&procHandles[0])
		n = needed
		ret2, _, err := pEnumProcessModules.Call(
			uintptr(hProc),
			uintptr(procHandlesPtr),
			uintptr(n),
			uintptr(unsafe.Pointer(&needed)))
		if ret2 == 0 {
			return nil, err
		}
		if int(ret2) == 1 {
			for i := 0; uint32(i) < needed/8; i++ {
				name := make([]uint16, 1024)
				windows.GetModuleFileNameEx(hProc, windows.Handle(procHandles[i]), &name[0], 260) // sizof WCHAR[MAX_PATH] / sizeof(WCHAR)
				moduleName := windows.UTF16PtrToString(&name[0])
				mod = append(mod, moduleName)
			}
		}
	}
	return mod, nil
}

func CheckIfDotnetDllLoaded(pid uint32) (bool, error) {
	name := fmt.Sprintf("\\BaseNamedObjects\\Cor_Private_IPCBlock_v4_%d", pid)
	sectionName := RtlInitUnicodeString(name)
	sectionName.MaximumLength -= 1
	objAttributes := InitializeObjectAttribute(sectionName, OBJ_CASE_INSENSITIVE, 0)
	var sectionHandle uintptr
	NTstatus := NtOpenSection(&sectionHandle, 0x001, objAttributes)
	if NTstatus == 0 {
		return true, nil
	} else {
		return false, nil
	}
}

func EnumModules(pid uint32) (string, error) {
	results := "Loaded Modules \n"
	hProc, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, pid)
	if err != nil {
		return "", err
	}
	var n uint32
	var needed uint32
	ret, _, err := pEnumProcessModules.Call(
		uintptr(hProc),
		0,
		uintptr(n),
		uintptr(unsafe.Pointer(&needed)))
	if ret == 0 {
		return "", err
	}
	if int(ret) == 1 && needed > 0 {
		procHandles := make([]syscall.Handle, needed)
		procHandlesPtr := unsafe.Pointer(&procHandles[0])
		n = needed
		ret2, _, err := pEnumProcessModules.Call(
			uintptr(hProc),
			uintptr(procHandlesPtr),
			uintptr(n),
			uintptr(unsafe.Pointer(&needed)))
		if ret2 == 0 {
			return "", err
		}
		if int(ret2) == 1 {
			for i := 0; uint32(i) < needed/8; i++ {
				name := make([]uint16, 1024)
				windows.GetModuleFileNameEx(hProc, windows.Handle(procHandles[i]), &name[0], 260) // sizof WCHAR[MAX_PATH] / sizeof(WCHAR)
				mInfo := windows.ModuleInfo{}
				moduleName := windows.UTF16PtrToString(&name[0])
				err = windows.GetModuleInformation(hProc, windows.Handle(procHandles[i]), &mInfo, uint32(unsafe.Sizeof(mInfo)))
				if err != nil {
					results += fmt.Sprintf("%s 0x???????????\n", moduleName)
					continue
				}
				results += fmt.Sprintf("%s %p\n", moduleName, unsafe.Pointer(mInfo.BaseOfDll))
			}
		}
	}
	return results, nil
}

func EnumDeviceDrivers() (string, error) {
	var lpImageBase [1024]uintptr
	var bytesNeeded uint32
	var driverCount uint32
	res, _, err := pEnumDeviceDrivers.Call(uintptr(unsafe.Pointer(&lpImageBase)), unsafe.Sizeof(lpImageBase), uintptr(unsafe.Pointer(&bytesNeeded)))
	if res == 0 || bytesNeeded > uint32(unsafe.Sizeof(lpImageBase)) {
		return "", err
	}
	driverCount = bytesNeeded / uint32(unsafe.Sizeof(lpImageBase[0]))
	result := fmt.Sprintf("Driver count %d\n", driverCount)
	for x := 0; x < int(driverCount); x++ {
		driverName := make([]byte, 50)
		b, _, err := pGetDeviceDriverBaseNameW.Call(lpImageBase[x], uintptr(unsafe.Pointer(&driverName[0])), unsafe.Sizeof(driverName)/unsafe.Sizeof(driverName[0]))
		if b == 0 {
			return "", err
		}
		result += fmt.Sprintf("%d %s\n", x, string(driverName))
		driverName = nil
	}
	return result, nil
}
