package winapi

import (
	"log"
	"syscall"
	"unsafe"
)

var (
	PModNtdll                 = syscall.NewLazyDLL("ntdll.dll")
	pRtlCopyMemory            = PModNtdll.NewProc("RtlCopyMemory")
	pNtProtectVirtualMemory   = PModNtdll.NewProc("NtProtectVirtualMemory")
	PNtCreateThread           = PModNtdll.NewProc("NtCreateThread")
	pNtOpenSection            = PModNtdll.NewProc("NtOpenSection")
	pRtlInitUnicodeString     = PModNtdll.NewProc("RtlInitUnicodeString")
	pNtQueryObject            = PModNtdll.NewProc("NtQueryObject")
	pNtDuplicateObject        = PModNtdll.NewProc("NtDuplicateObject")
	pNtQuerySystemInformation = PModNtdll.NewProc("NtQuerySystemInformation")
)

const (
	OBJ_INHERIT            = 0x00000002
	OBJ_PERMANENT          = 0x00000010
	OBJ_EXCLUSIVE          = 0x00000020
	OBJ_CASE_INSENSITIVE   = 0x00000040
	OBJ_OPENIF             = 0x00000080
	OBJ_OPENLINK           = 0x00000100
	OBJ_KERNEL_HANDLE      = 0x00000200
	OBJ_FORCE_ACCESS_CHECK = 0x00000400
	OBJ_VALID_ATTRIBUTES   = 0x000007F2
	SECTION_QUERY          = 0x000001
	SECTION_MAP_WRITE      = 0x000002
	SECTION_MAP_READ       = 0x000004
	SECTION_MAP_EXECUTE    = 0x000008
	SECTION_EXTEND_SIZE    = 0x000010
	SECTION_ALL_ACCESS     = 0x0F001F
	DUPLICATE_SAME_ACCESS  = 0x00000002
)

type GenericMapping struct {
	GenericRead    uint32
	GenericWrite   uint32
	GenericExecute uint32
	GenericAll     uint32
}

type ObjectTypeInformationT struct {
	TypeName                   UnicodeString
	TotalNumberOfObjects       uint32
	TotalNumberOfHandles       uint32
	TotalPagedPoolUsage        uint32
	TotalNonPagedPoolUsage     uint32
	TotalNamePoolUsage         uint32
	TotalHandleTableUsage      uint32
	HighWaterNumberOfObjects   uint32
	HighWaterNumberOfHandles   uint32
	HighWaterPagedPoolUsage    uint32
	HighWaterNonPagedPoolUsage uint32
	HighWaterNamePoolUsage     uint32
	HighWaterHandleTableUsage  uint32
	InvalidAttributes          uint32
	GenericMapping             GenericMapping
	ValidAccessMask            uint32
	SecurityRequired           bool
	MaintainHandleCount        bool
	TypeIndex                  byte
	ReservedByte               byte
	PoolType                   uint32
	DefaultPagedPoolCharge     uint32
	DefaultNonPagedPoolCharge  uint32
}

type SystemHandleTableEntry struct {
	UniqueProcessId       uint16
	CreatorBackTraceIndex uint16
	ObjectTypeIndex       byte
	HandleAttributes      byte
	HandleValue           uint16
	Object                uintptr
	GrantedAccess         uint32
}

type SystemHandleEntry struct {
	OwnerPid      uint32
	ObjectType    byte
	HandleFlags   byte
	HandleValue   uint16
	ObjectPointer *byte
	AccessMask    uint32
}

type SystemHandleInformationT struct {
	Count   uint32
	Handles [1]SystemHandleTableEntry
}

type UnicodeString struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type ObjectAttributes struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               *UnicodeString
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}

func NtQuerySystemInformation(
	SystemInformationClass uint32, //SystemInformationClass,
	SystemInformation *byte,
	SystemInformationLength uint32,
	ReturnLength *uint32,
) uint32 {
	r0, _, _ := pNtQuerySystemInformation.Call(uintptr(SystemInformationClass),
		uintptr(unsafe.Pointer(SystemInformation)),
		uintptr(SystemInformationLength),
		uintptr(unsafe.Pointer(ReturnLength)))
	return uint32(r0)
}

func NtDuplicateObject(
	SourceProcessHandle uintptr,
	SourceHandle uintptr,
	TargetProcessHandle uintptr,
	TargetHandle *uintptr,
	DesiredAccess uint32, //AccessMask,
	HandleAttributes uint32,
	Options uint32,
) uint32 {
	r0, _, _ := pNtDuplicateObject.Call(uintptr(SourceProcessHandle),
		uintptr(SourceHandle),
		uintptr(TargetProcessHandle),
		uintptr(unsafe.Pointer(TargetHandle)),
		uintptr(DesiredAccess),
		uintptr(HandleAttributes),
		uintptr(Options))
	return uint32(r0)
}

func NtQueryObject(
	Handle uintptr,
	ObjectInformationClass uint32, //ObjectInformationClass,
	ObjectInformation *byte,
	ObjectInformationLength uint32,
	ReturnLength *uint32,
) uint32 {
	r0, _, _ := pNtQueryObject.Call(uintptr(Handle),
		uintptr(ObjectInformationClass),
		uintptr(unsafe.Pointer(ObjectInformation)),
		uintptr(ObjectInformationLength),
		uintptr(unsafe.Pointer(ReturnLength)))
	return uint32(r0)
}

// InitializeObjectAttribute macro
func InitializeObjectAttribute(name *UnicodeString, attr uint32, root uintptr) (initializedAttributes *ObjectAttributes) {
	initializedAttributes = &ObjectAttributes{}
	initializedAttributes.Length = 48
	initializedAttributes.ObjectName = name
	initializedAttributes.Attributes = attr
	initializedAttributes.RootDirectory = root
	initializedAttributes.SecurityDescriptor = 0
	initializedAttributes.SecurityQualityOfService = 0
	return initializedAttributes
}

func RtlInitUnicodeString(src string) (dest *UnicodeString) {
	/* void RtlInitUnicodeString(
	   PUNICODE_STRING DestinationString,
	   PCWSTR          SourceString
	 ); */
	dest = &UnicodeString{}
	pRtlInitUnicodeString.Call(
		uintptr(unsafe.Pointer(dest)),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(src))),
	)
	return dest
}

func NtOpenSection(
	SectionHandle *uintptr,
	DesiredAccess uint32,
	ObjectAttributes *ObjectAttributes,
) uint32 {
	r0, _, _ := pNtOpenSection.Call(uintptr(unsafe.Pointer(SectionHandle)),
		uintptr(DesiredAccess),
		uintptr(unsafe.Pointer(ObjectAttributes)))
	log.Println(uint32(r0))
	return uint32(r0)
}

func NtProtectVirtualMemory(hProcess uintptr, baseAddr uintptr, bytesToProtect *uintptr, newProt uint32, oldProt *uint32) error {
	ntstatus, _, _ := pNtProtectVirtualMemory.Call(hProcess, uintptr(unsafe.Pointer(&baseAddr)), uintptr(unsafe.Pointer(bytesToProtect)), uintptr(newProt), uintptr(unsafe.Pointer(oldProt)))
	if ntstatus != 0 {
		log.Printf("%x", ntstatus)
		return syscall.GetLastError()
	}
	log.Println("nt prot worked")
	return nil
}

// /	_, _, err = windows.RtlCopyMemory.Call(heap, uintptr(unsafe.Pointer(&shellcode[0])), uintptr(shellcodeLen))
func RtlCopyMemory(destination uintptr, source uintptr, length uint32) error {
	//uintptr(unsafe.Pointer(&shellcode[0]))
	_, _, err := pRtlCopyMemory.Call(destination, source, uintptr(length))
	if err != nil {
		return err
	}
	return nil
}
