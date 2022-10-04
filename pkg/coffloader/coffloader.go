package coffloader

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"strings"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

const (
	MEM_SYMNAME_MAX                  = 100
	IMAGE_SCN_MEM_WRITE              = 0x80000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
	IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
	IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
	IMAGE_SCN_MEM_SHARED             = 0x10000000
	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
)

type COFF_FILE_HEADER struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint16
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

// 40 bytes
type COFF_SECTION struct {
	Name                 [8]byte
	VirtualSize          uint32
	VirtualAddress       uint32
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	PointerToLineNumbers uint32
	NumberOfRelocations  uint16
	NumberOfLineNumbers  uint16
	Characteristics      uint32
}

// 10 bytes
type COFF_RELOCATION struct {
	VirtualAddress   uint32
	SymbolTableIndex uint32
	Type             uint16
}

// 18 bytes
type COFF_SYMBOL struct {
	/*
		union {
			char ShortName[8]
			struct {
				uint32_t Zeros;
				uint32_t Offset;
			};
		}
	*/
	ShortName          [8]byte
	Value              uint32
	SectionNumber      uint16
	Type               uint16
	StorageClass       uint8
	NumberOfAuxSymbols uint8
}

type COFF_MEM_SECTION struct {
	Counter              uint32
	Name                 [10]byte
	SizeOfRawData        uint32
	PointerToRawData     uint32
	PointerToRelocations uint32
	NumberOfRelocations  uint16
	Characteristics      uint32
	InMemoryAddress      uintptr
	InMemorySize         uint32
}

type COFF_SYM_ADDRESS struct {
	Counter         uint32
	Name            [MEM_SYMNAME_MAX]byte
	SectionNumber   uint16
	Value           uint32
	StorageClass    uint8
	InMemoryAddress uint64
	GOTAddress      uint64
}

///

func cleanup(allocs []uintptr) {
	for _, a := range allocs {
		winapi.VirtualFree(a, 0, winapi.MEM_RELEASE)
	}
}

func ParseCoff(coff []byte) (string, error) {
	// parse header
	allocationAddresses := make([]uintptr, 0)
	coffHdrPtr := (*COFF_FILE_HEADER)(unsafe.Pointer(&coff[0]))
	headerOffset := unsafe.Sizeof(COFF_FILE_HEADER{})
	sectionSize := unsafe.Sizeof(COFF_SECTION{})
	totalSectionSize := sectionSize * uintptr(coffHdrPtr.NumberOfSections)
	var coffRelocPtr *COFF_RELOCATION
	var coffSymbolPtr *COFF_SYMBOL
	var baseAddressOfMemory uintptr
	var err error
	// allocate memory for all sections here
	baseAddressOfMemory, err = winapi.VirtualAlloc(0, uint32(totalSectionSize), winapi.MEM_COMMIT|winapi.MEM_RESERVE, winapi.PAGE_READWRITE)
	if err != nil {
		return "", err
	}
	allocationAddresses = append(allocationAddresses, baseAddressOfMemory)
	memorySections := (*COFF_MEM_SECTION)(unsafe.Pointer(baseAddressOfMemory))
	// parse sections
	for x := 0; x < int(coffHdrPtr.NumberOfSections); x++ {
		coffSectionPtr := (*COFF_SECTION)(unsafe.Pointer(&coff[headerOffset+sectionSize*uintptr(x)]))
		if coffSectionPtr.SizeOfRawData < 0 {
			// no data to save in this section.
		} else {
			// copy section to memory
			memorySections.Counter = uint32(x)
			copy(memorySections.Name[:], coffSectionPtr.Name[:])
			memorySections.SizeOfRawData = coffSectionPtr.SizeOfRawData
			memorySections.PointerToRawData = coffSectionPtr.PointerToRawData
			memorySections.PointerToRelocations = coffSectionPtr.PointerToRelocations
			memorySections.NumberOfRelocations = coffSectionPtr.NumberOfRelocations
			memorySections.Characteristics = coffSectionPtr.Characteristics
			memorySections.InMemorySize = memorySections.SizeOfRawData + (0x1000 - memorySections.SizeOfRawData%0x1000)
			// check if needs to be executable
			if memorySections.Characteristics&IMAGE_SCN_CNT_CODE != 0 {
				memorySections.InMemoryAddress, err = winapi.VirtualAlloc(0, memorySections.InMemorySize, winapi.MEM_COMMIT|winapi.MEM_TOP_DOWN, winapi.PAGE_READWRITE)
				if err != nil {
					cleanup(allocationAddresses)
					return "", err
				}
			}
			memorySections.InMemoryAddress, err = winapi.VirtualAlloc(0, memorySections.InMemorySize, winapi.MEM_COMMIT|winapi.MEM_TOP_DOWN, winapi.PAGE_EXECUTE_READWRITE)
			if err != nil {
				cleanup(allocationAddresses)
				return "", err
			}
			allocationAddresses = append(allocationAddresses, memorySections.InMemoryAddress)
			var wrote uint32
			success, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), memorySections.InMemoryAddress, uintptr(unsafe.Pointer(&coff[0]))+uintptr(coffSectionPtr.PointerToRawData), coffSectionPtr.SizeOfRawData, &wrote)
			if !success {
				cleanup(allocationAddresses)
				return "", err
			}
			if memorySections.NumberOfRelocations != 0 {
				// print relocation table
				for i := 0; i < int(memorySections.NumberOfRelocations); i++ {
					coffRelocPtr = (*COFF_RELOCATION)(unsafe.Pointer(&coff[memorySections.PointerToRelocations+uint32(10*i)]))
				}
			}
			// increase memory sections pointer
			memorySections = (*COFF_MEM_SECTION)(unsafe.Pointer(uintptr(unsafe.Pointer(memorySections)) + unsafe.Sizeof(COFF_MEM_SECTION{})))
		}
	}
	/// allocate memory for symbol table
	numSymbols := coffHdrPtr.NumberOfSymbols
	symAddrSize := uint32(unsafe.Sizeof(COFF_SYM_ADDRESS{}))
	memSymbolsBaseAddress, err := winapi.VirtualAlloc(0, symAddrSize*numSymbols, winapi.MEM_COMMIT|winapi.MEM_RESERVE, winapi.PAGE_READWRITE)
	if err != nil {
		cleanup(allocationAddresses)
		return "", err
	}
	allocationAddresses = append(allocationAddresses, memSymbolsBaseAddress)
	memSymbols := (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress))
	// got start of symbol table
	coffSymbolPtr = (*COFF_SYMBOL)(unsafe.Pointer(&coff[coffHdrPtr.PointerToSymbolTable]))
	coffStringsPtr := (*byte)(unsafe.Pointer(&coff[coffHdrPtr.PointerToSymbolTable+numSymbols*18]))
	// print symbols table
	for i := 0; i < int(numSymbols); i++ {
		if coffSymbolPtr.SectionNumber == 0 && coffSymbolPtr.StorageClass == 0 {
			copy(memSymbols.Name[:], "__UNDEFINED")
		} else {
			if coffSymbolPtr.ShortName[3] != 0 || coffSymbolPtr.ShortName[0] != 0 {
				n := make([]byte, 10)
				copy(n, coffSymbolPtr.ShortName[0:8])
				copy(memSymbols.Name[:], n)
			} else {
				strLoc := (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(coffStringsPtr)) + uintptr(uint32(binary.LittleEndian.Uint32(coffSymbolPtr.ShortName[4:])))))
				// copy string to our memory.
				var counter = 0
				for {
					if *strLoc == 0 {
						break
					}
					memSymbols.Name[counter] = *strLoc
					counter++
					strLoc = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(strLoc)) + 1))
				}
			}
		}
		// save data in internal symbols table that we allocated
		memSymbols.Counter = uint32(i)
		memSymbols.SectionNumber = coffSymbolPtr.SectionNumber
		memSymbols.Value = coffSymbolPtr.Value
		memSymbols.StorageClass = coffSymbolPtr.StorageClass
		memSymbols.InMemoryAddress = 0
		// increase both pointers
		coffSymbolPtr = (*COFF_SYMBOL)(unsafe.Pointer(uintptr(unsafe.Pointer(coffSymbolPtr)) + 18))
		memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})))
	}
	got, err := winapi.VirtualAlloc(0, 2048, winapi.MEM_COMMIT|winapi.MEM_RESERVE|winapi.MEM_TOP_DOWN, winapi.PAGE_READWRITE)
	if err != nil {
		cleanup(allocationAddresses)
		return "", err
	}
	allocationAddresses = append(allocationAddresses, got)
	// resolve symbols
	entryPoint, err := ResolveSymbols(got, memSymbolsBaseAddress, numSymbols, baseAddressOfMemory)
	if err != nil {
		cleanup(allocationAddresses)
		return "", err
	}
	for i := 0; i < int(numSymbols); i++ {
		memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbolsBaseAddress)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(i)))
	}
	//fix relocations.
	memorySections = (*COFF_MEM_SECTION)(unsafe.Pointer(baseAddressOfMemory))
	for i := 0; i < int(coffHdrPtr.NumberOfSections); i++ {
		memorySectionPtr := (*COFF_MEM_SECTION)(unsafe.Pointer(uintptr(unsafe.Pointer(memorySections)) + uintptr(unsafe.Sizeof(COFF_MEM_SECTION{})*uintptr(i))))
		if memorySectionPtr.NumberOfRelocations == 0 {
			continue
		}
		for j := 0; j < int(memorySectionPtr.NumberOfRelocations); j++ {
			coffRelocPtr = (*COFF_RELOCATION)(unsafe.Pointer(&coff[memorySectionPtr.PointerToRelocations+uint32(10*j)]))
			switch coffRelocPtr.Type {
			case 0x1:
				// untested
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				offset64 := uint64(where)
				what64 := (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress + offset64
				ok, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&what64)), 8, nil)
				if !ok {
					cleanup(allocationAddresses)
					return "", err
				}
				break
			case 0x3:
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				var offset32 [4]byte
				ok, err := winapi.ReadProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&offset32[0])), 4, nil)
				if !ok {
					cleanup(allocationAddresses)
					return "", err
				}
				offset32Num := binary.LittleEndian.Uint32(offset32[:])
				var what3232 uint32
				what32 := uint32(offset32Num) + uint32((*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress) - uint32(where+4)
				what3232 = uint32(what32)
				ok, err = winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&what3232)), 4, nil)
				if !ok {
					cleanup(allocationAddresses)
					return "", err
				}
				break
			case 0x4:
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				var offset32 [4]byte
				ok, err := winapi.ReadProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&offset32[0])), 4, nil)
				if !ok {
					cleanup(allocationAddresses)
					return "", err
				}
				offset32Num := binary.LittleEndian.Uint32(offset32[:])
				var what3232 uint32
				if (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).GOTAddress != 0 {
					what32 := (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).GOTAddress - uint64(where+4)
					what3232 = uint32(what32)
				} else {
					what32 := uint64(offset32Num) + (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress - uint64(where+4)
					what3232 = uint32(what32)
				}
				ok, err = winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&what3232)), 4, nil)
				if !ok {
					cleanup(allocationAddresses)
					return "", err
				}
				break
			case 0x8:
				//untested
				where := memorySectionPtr.InMemoryAddress + uintptr(coffRelocPtr.VirtualAddress)
				var offset32 [4]byte
				ok, err := winapi.ReadProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&offset32[0])), 4, nil)
				if !ok {
					cleanup(allocationAddresses)
					return "", err
				}
				offset32Num := binary.LittleEndian.Uint32(offset32[:])
				var what3232 uint32
				what32 := uint32(offset32Num) + uint32((*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress+uintptr(unsafe.Sizeof(COFF_SYM_ADDRESS{})*uintptr(coffRelocPtr.SymbolTableIndex)))).InMemoryAddress) - uint32(where+4+4)
				what3232 = uint32(what32)
				ok, err = winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), where, uintptr(unsafe.Pointer(&what3232)), 4, nil)
				if !ok {
					cleanup(allocationAddresses)
					return "", err
				}
				break
			default:
				cleanup(allocationAddresses)
				return "", fmt.Errorf("Allocation type not supported")
			}
		}
	}
	hWnd := winapi.GetConsoleWindow()
	// no stdout try to use a file instead
	if hWnd == 0 {
		f, err := ioutil.TempFile("", "*.log")
		if err != nil {
			cleanup(allocationAddresses)
			return "", err
		}
		name := f.Name()
		f.Close() // close file.
		hFile := winapi.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, 0, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if hFile == 0 {
			cleanup(allocationAddresses)
			return "", fmt.Errorf("Failed to get handle to tmp file")
		}
		err = winapi.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(hFile))
		if err != nil {
			cleanup(allocationAddresses)
			return "", err
		}
		hThread, err := winapi.CreateThread(0, 0, uintptr(entryPoint), 0, 0, nil)
		if err != nil {
			cleanup(allocationAddresses)
			return "", err
		}
		windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
		windows.CloseHandle(windows.Handle(hFile))
		hStdout, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
		windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, hStdout)
		data, err := ioutil.ReadFile(name)
		if err != nil {
			cleanup(allocationAddresses)
			return "", err
		}
		os.Remove(name)
		var result = string(data)
		cleanup(allocationAddresses)
		return fmt.Sprintf("COFFEE STDOUT: %s", result), nil
	}
	ogStdout, NewStdout := winapi.CaptureStdout()
	hThread, err := winapi.CreateThread(0, 0, uintptr(entryPoint), 0, 0, nil)
	if err != nil {
		cleanup(allocationAddresses)
		return "", err
	}
	windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
	winapi.RevertStdout(ogStdout, NewStdout)
	var result string = winapi.GetStdoutBuffer()
	cleanup(allocationAddresses)
	return fmt.Sprintf("COFFEE STDOUT: %s", result), nil
}

func ResolveSymbols(GOT uintptr, memSymbolsBaseAddress uintptr, nSymbols uint32, memSectionsBaseAddress uintptr) (uintptr, error) {
	GOTIdx := 0
	memSymbols := (*COFF_SYM_ADDRESS)(unsafe.Pointer(memSymbolsBaseAddress))
	memorySections := (*COFF_MEM_SECTION)(unsafe.Pointer(memSectionsBaseAddress))
	var symbol [256]byte
	var strSymbol string
	var dllName string
	var funcName string
	var entryPoint uintptr
	section := 0
	for i := 0; i < int(nSymbols); i++ {
		copy(symbol[:], memSymbols.Name[:])
		strSymbol = trimstr(string(symbol[:]))
		memSymbols.GOTAddress = 0
		if memSymbols.SectionNumber > 0xff {
			memSymbols.InMemoryAddress = 0
			memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})))
			continue
		}
		if strings.Contains(strSymbol, "__UNDEFINED") {
			memSymbols.InMemoryAddress = 0
			memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})))
			continue
		}
		if strings.Contains(strSymbol, "imp_") {
			if !strings.Contains(strSymbol, "$") {
				dllName = "kernel32"
				funcName = strings.Split(strSymbol, "__imp_")[1]
			} else {
				dllName = strings.Split(strSymbol, "__imp_")[1]
				dllName = strings.Split(dllName, "$")[0]
				funcName = strings.Split(strSymbol, "$")[1]
			}
			lib, err := syscall.LoadLibrary(dllName + ".dll")
			if err != nil {
				return 0, err
			}
			if lib != 0 {
				funcAddress, err := syscall.GetProcAddress(lib, funcName)
				if funcAddress == 0 {
					return 0, err
				}
				//funcAddress := winapi.GetProcAddress(lib, funcName)
				if funcAddress == 0 {
					return 0, fmt.Errorf("failed to get proc address")
				}
				memSymbols.InMemoryAddress = uint64(funcAddress)
				var wrote uint32
				ok, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), GOT+(uintptr(GOTIdx)*8), uintptr(unsafe.Pointer(&memSymbols.InMemoryAddress)), 8, &wrote)
				if !ok {
					return 0, err
				}
				memSymbols.GOTAddress = uint64(GOT + (uintptr(GOTIdx * 8))) //uint64((GOT + (uintptr(GOTIdx) * 8)))
				GOTIdx++
			}
		} else {
			section = int(memSymbols.SectionNumber) - 1
			movedPtr := (*COFF_MEM_SECTION)(unsafe.Pointer(uintptr(unsafe.Pointer(memorySections)) + uintptr((unsafe.Sizeof(COFF_MEM_SECTION{}) * uintptr(section)))))
			memSymbols.InMemoryAddress = uint64(movedPtr.InMemoryAddress + uintptr(memSymbols.Value))
			if strSymbol == "go" {
				entryPoint = uintptr(memSymbols.InMemoryAddress)
			}
		}
		// move pointer
		memSymbols = (*COFF_SYM_ADDRESS)(unsafe.Pointer(uintptr(unsafe.Pointer(memSymbols)) + unsafe.Sizeof(COFF_SYM_ADDRESS{})))
	}
	return entryPoint, nil
}

func trimstr(old string) string {
	var new = ""
	for _, c := range old {
		if c == 0 {
			break
		}
		new += string(c)
	}
	return new
}
