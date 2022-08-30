package peloader

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
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

func CopySectionsToMemory(dll *pe.File, peHeaderOptionalHeader64 *pe.OptionalHeader64, baseAddress uintptr) ([]MemorySection, error) {
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
	peType              PeType
	rawData             []byte
	peStruct            *pe.File
	peHeaders           *pe.OptionalHeader64
	alignedImageSize    uint32
	removeHeader        bool
	peEntry             uintptr
	allocatedMemoryBase uintptr
	// other stuff here in the future like exports
	// delete header flags etcs
}

func NewRawPE(peT PeType, removeDOSHeaders bool, data []byte) *RawPe {
	return &RawPe{
		peType:       peT,
		rawData:      data,
		peStruct:     nil,
		removeHeader: removeDOSHeaders,
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

func (r *RawPe) LoadPEFromMemory() error {
	buffer := bytes.NewBuffer(r.rawData)
	peFile, err := pe.NewFile(bytes.NewReader(buffer.Bytes()))
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to load pe file %v", err))
	}
	r.peStruct = peFile
	if !DosHeaderCheck(r.rawData) {
		return errors.New("Dos header check failed.")
	}
	// only support 64 bit.
	r.peHeaders = r.peStruct.OptionalHeader.(*pe.OptionalHeader64)
	if (r.peHeaders.SectionAlignment & 1) != 0 {
		return (errors.New("Unknown Alignment error."))
	}
	//alignedImgSize := AlignValueUp(r.peHeaders.SizeOfImage, uint32(PAGE_SIZE))
	r.alignedImageSize = AlignValueUp(r.peHeaders.SizeOfImage, uint32(PAGE_SIZE))
	if r.alignedImageSize != AlignValueUp(r.peStruct.Sections[r.peStruct.NumberOfSections-1].VirtualAddress+r.peStruct.Sections[r.peStruct.NumberOfSections-1].Size, uint32(PAGE_SIZE)) {
		return errors.New("Failed to align image.")
	}
	// allocating memory chunk for image.
	var baseAddressOfMemoryAlloc uintptr
	prefBaseAddr := uintptr(r.peHeaders.ImageBase)
	baseAddressOfMemoryAlloc, err = winapi.VirtualAlloc(uintptr(r.peHeaders.ImageBase), r.alignedImageSize, winapi.MEM_RESERVE|winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
	if baseAddressOfMemoryAlloc == 0 {
		//log.Println("Failed to allocate at preffered base address...Attempting to allocate anywhere else.")
		baseAddressOfMemoryAlloc, err = winapi.VirtualAlloc(uintptr(0), r.alignedImageSize, winapi.MEM_RESERVE|winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
		if err != nil {
			return errors.New(fmt.Sprintf("Failed to allocate memory at random location %v", err))
		}
	}
	// base memory chunk allocated.
	peHead, err := winapi.VirtualAlloc(baseAddressOfMemoryAlloc, r.peHeaders.SizeOfHeaders, winapi.MEM_COMMIT, winapi.PAGE_READWRITE)
	if peHead == 0 {
		return errors.New(fmt.Sprintf("Failed to commit memory for pe headers %v", err))
	}
	// committed memory for pe headers.
	var wrote uint32
	if ok, err := winapi.WriteProcessMemory(syscall.Handle(winapi.GetCurrentProcess()), peHead, uintptr(unsafe.Pointer(&r.rawData[0])), r.peHeaders.SizeOfHeaders, &wrote); !ok {
		return errors.New(fmt.Sprintf("Failed to write pe headers to memory %v", err))
	}
	// wrote pe headers to memory
	r.peHeaders.ImageBase = uint64(baseAddressOfMemoryAlloc)
	// updating pe header to reflect base address (just incase it changed)
	// now you commit sections in the memory block and copy the sections to the proper locations
	memSections, err := CopySectionsToMemory(r.peStruct, r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		return err
	}
	//base relocations if preferred base address is doesnt match where we allocated memory
	baseAddressDiff := uint64(baseAddressOfMemoryAlloc - prefBaseAddr)
	if baseAddressDiff != 0 {
		if err := BaseRelocate(baseAddressDiff, baseAddressOfMemoryAlloc, *r.peHeaders); err != nil {
			return errors.New(fmt.Sprintf("Failed to base relocate %v", err))
		}
	}
	err = CreateImportAddressTable(r.peHeaders, baseAddressOfMemoryAlloc)
	if err != nil {
		return err
	}
	err = FinalizeSections(r.peStruct, r.peHeaders, baseAddressOfMemoryAlloc, memSections)
	if err != nil {
		return err
	}
	// remove dos headers (OPTIONAL)
	/*if r.removeHeader {
		RemoveDOSHeader(baseAddressOfMemoryAlloc)
	}*/
	RemoveDOSHeader(baseAddressOfMemoryAlloc)
	//ExecuteTLSCallbacks TODO
	entryPointPtr := unsafe.Pointer(uintptr(r.peHeaders.AddressOfEntryPoint) + baseAddressOfMemoryAlloc)
	//runtime.LockOSThread()
	r.peEntry = uintptr(entryPointPtr)
	r.allocatedMemoryBase = baseAddressOfMemoryAlloc
	switch r.peType {
	case Dll:
		// calling dll entry point
		syscall.Syscall(uintptr(entryPointPtr), 3, baseAddressOfMemoryAlloc, 1, 0)
		break
	case Exe:
		// calling exe entry point no args
		// we are not patching exitThread so when exes exit they will crash process
		// exe needs to call exitThread before exiting and needs to be run in seperate thread
		hThread, err := winapi.CreateThread(0, 0, uintptr(entryPointPtr), 0, 0, nil)
		if err != nil {
			return err
		}
		windows.WaitForSingleObject(windows.Handle(hThread), windows.INFINITE)
		break
	default:
		return errors.New("Provided Invalid PE Type")
	}
	//runtime.UnlockOSThread()
	return nil
}

func (r *RawPe) FreePeFromMemory() error {
	err := windows.VirtualFree(uintptr(r.peHeaders.ImageBase), 0, winapi.MEM_RELEASE)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to free PE memory allocation %v", err))
	}
	return err
}

func (r *RawPe) FreePeDllFromMemory() error {
	// calling dll detach.
	syscall.Syscall(r.peEntry, 3, r.allocatedMemoryBase, 0, 0)
	err := windows.VirtualFree(uintptr(r.peHeaders.ImageBase), 0, winapi.MEM_RELEASE)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to free PE memory allocation %v", err))
	}
	return err
}

func DosHeaderCheck(rawPeFileData []byte) bool {
	dosHeaderStruct := (*ImageDOSHeader)(unsafe.Pointer(&rawPeFileData[0]))
	if dosHeaderStruct.Magic != IMAGE_DOS_SIGNATURE {
		return false
	}
	return true
}

/////

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
