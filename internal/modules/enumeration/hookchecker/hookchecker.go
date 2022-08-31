package hookchecker

import (
	"fmt"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

//NtCreateThread
//NtCreateThreadEx
//NtAllocateVirtualMemory
//NtWriteVirtualMemory
//NtProtectVirtualMemory

func HookChecker(dllName string) (string, error) {
	name, err := windows.UTF16PtrFromString("NtCreateThread")
	lib, err := windows.LoadLibrary("ntdll")
	if err != nil {
		return "", err
	}
	pNtCreateThread, err := winapi.GetProcAddress(uintptr(lib), name)
	if err != nil {
		return "", err
	}
	hooked := CheckHook(pNtCreateThread)
	if !hooked {
		return "[-] Not Hooked", nil
	}
	return "[+] Hooked", nil
}

func CheckHook(funcStart uintptr) bool {
	bytePtr := (*byte)(unsafe.Pointer(funcStart))
	byteArray := make([]byte, 10)
	for x := 0; x < 10; x++ {
		byteArray[x] = *bytePtr
	}
	fmt.Printf("Opcode -> %x\n", byteArray[0])
	if byteArray[0] == 0xE9 {
		return true
	}
	if byteArray[0] == 0x68 && byteArray[5] == 0xC3 {
		return true
	}
	return false
}

/*
	dosHeader := (*peloader.ImageDOSHeader)(unsafe.Pointer(dllHandle))
	imageNtHeader := (*peloader.ImageNtHeader)(unsafe.Pointer(uintptr(dllHandle) + uintptr(dosHeader.AddressOfNewEXEHeader)))
	optionalHeader := imageNtHeader.OptionalHeader.(pe.OptionalHeader64)
	exportDirectory := (*peloader.ImageExportDirectory)(unsafe.Pointer(uintptr(unsafe.Pointer(dllHandle)) + uintptr(optionalHeader.DataDirectory[0].VirtualAddress)))
	nname := (*uint32)(unsafe.Pointer(uintptr(dllHandle) + uintptr(exportDirectory.AddressOfNames)))
	for x := 0; uint32(x) < exportDirectory.NumberOfNames; x++ {
		nameStart := (*byte)(unsafe.Pointer(nname))
		log.Printf("%c\n", *nameStart)
		nname = (*uint32)(unsafe.Pointer(uintptr(unsafe.Pointer(nname)) + uintptr(8)))
	}
	//offset := unsafe.Sizeof(pe.FileHeader{}) + unsafe.Sizeof(uint32(1))
	//textPtr := uintptr(unsafe.Pointer(imageNtHeader)) + offset + uintptr(imageNtHeader.FileHeader.SizeOfOptionalHeader)
	//textSection := (*pe.SectionHeader32)(unsafe.Pointer(textPtr))
*/
