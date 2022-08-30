package loadlibrary

import (
	"debug/pe"
	"fmt"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/peloader"
	"golang.org/x/sys/windows"
)

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
	/*
		h, err := windows.GetModuleHandleEx()
		if err != nil {
			return "", err
		}
		err = windows.FreeLibrary(h)
		if err != nil {
			return "", err
		}
		err = windows.FreeLibrary(h)
		if err != nil {
			return "", err
		}
	*/
	return fmt.Sprintf("[+] Freed dll"), nil
}
