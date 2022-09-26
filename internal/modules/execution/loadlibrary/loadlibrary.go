package loadlibrary

import (
	"debug/pe"
	"fmt"
	"strconv"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/peloader"
	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func EnumDll(pid string) (string, error) {
	iPid, err := strconv.Atoi(pid)
	if err != nil {
		return "", err
	}
	return winapi.EnumModules(uint32(iPid))
}

func LoadDll(name string) (string, error) {
	moduleHandle, err := windows.LoadLibrary(name)
	if err != nil {
		return "", err
	}
	dosHeader := (*peloader.ImageDOSHeader)(unsafe.Pointer(moduleHandle))
	imageNtHeader := (*peloader.ImageNtHeader)(unsafe.Pointer(uintptr(moduleHandle) + uintptr(dosHeader.AddressOfNewEXEHeader)))
	offset := unsafe.Sizeof(pe.FileHeader{}) + unsafe.Sizeof(uint32(1))
	textPtr := uintptr(unsafe.Pointer(imageNtHeader)) + offset + uintptr(imageNtHeader.FileHeader.SizeOfOptionalHeader)
	textSection := (*pe.SectionHeader32)(unsafe.Pointer(textPtr))
	return fmt.Sprintf("[+] Loaded dll %s at %p .text size -> %d", name, unsafe.Pointer(moduleHandle), textSection.VirtualSize), nil
}

func FreeDll(name string) (string, error) {
	p, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", err
	}
	var handle windows.Handle
	err = windows.GetModuleHandleEx(0x00000002, p, &handle)
	if err != nil {
		return "", err
	}
	err = windows.FreeLibrary(handle)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[+] Freed dll"), nil
}
