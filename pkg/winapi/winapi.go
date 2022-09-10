package winapi

const (
	MEM_COMMIT  = 0x1000
	MEM_RESERVE = 0x2000
	MEM_RELEASE = 0x8000

	PROCESS_CREATE_PROCESS            = 0x0080
	PROCESS_CREATE_THREAD             = 0x0002
	PROCESS_DUP_HANDLE                = 0x0040
	PROCESS_QUERY_INFORMATION         = 0x0400
	PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
	PROCESS_SET_INFORMATION           = 0x0200
	PROCESS_SET_QUOTA                 = 0x0100
	PROCESS_SUSPEND_RESUME            = 0x0800
	PROCESS_TERMINATE                 = 0x0001
	PROCESS_VM_OPERATION              = 0x0008
	PROCESS_VM_READ                   = 0x0010
	PROCESS_VM_WRITE                  = 0x0020
	//PROCESS_ALL_ACCESS                = 0x001F0FFF

	CREATE_SUSPENDED = 0x00000004

	SIZE     = 64 * 1024
	INFINITE = 0xFFFFFFFF

	PAGE_NOACCESS          = 0x00000001
	PAGE_READONLY          = 0x00000002
	PAGE_READWRITE         = 0x00000004
	PAGE_WRITECOPY         = 0x00000008
	PAGE_EXECUTE           = 0x00000010
	PAGE_EXECUTE_READ      = 0x00000020
	PAGE_EXECUTE_READWRITE = 0x00000040
	PAGE_EXECUTE_WRITECOPY = 0x00000080
	PAGE_GUARD             = 0x00000100
	PAGE_NOCACHE           = 0x00000200
	PAGE_WRITECOMBINE      = 0x00000400

	DELETE                   = 0x00010000
	READ_CONTROL             = 0x00020000
	WRITE_DAC                = 0x00040000
	WRITE_OWNER              = 0x00080000
	SYNCHRONIZE              = 0x00100000
	STANDARD_RIGHTS_READ     = READ_CONTROL
	STANDARD_RIGHTS_WRITE    = READ_CONTROL
	STANDARD_RIGHTS_EXECUTE  = READ_CONTROL
	STANDARD_RIGHTS_REQUIRED = DELETE | READ_CONTROL | WRITE_DAC | WRITE_OWNER
	STANDARD_RIGHTS_ALL      = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE
	TOKEN_ASSIGN_PRIMARY     = 0x0001
	TOKEN_DUPLICATE          = 0x0002
	TOKEN_IMPERSONATE        = 0x0004
	TOKEN_QUERY              = 0x0008
	TOKEN_QUERY_SOURCE       = 0x0010
	TOKEN_ADJUST_PRIVILEGES  = 0x0020
	TOKEN_ADJUST_GROUPS      = 0x0040
	TOKEN_ADJUST_DEFAULT     = 0x0080
	TOKEN_ADJUST_SESSIONID   = 0x0100
	TOKEN_ALL_ACCESS         = (STANDARD_RIGHTS_REQUIRED |
		TOKEN_ASSIGN_PRIMARY |
		TOKEN_DUPLICATE |
		TOKEN_IMPERSONATE |
		TOKEN_QUERY |
		TOKEN_QUERY_SOURCE |
		TOKEN_ADJUST_PRIVILEGES |
		TOKEN_ADJUST_GROUPS |
		TOKEN_ADJUST_DEFAULT |
		TOKEN_ADJUST_SESSIONID)
)

var (
	NullRef int
)

const (
	CONTEXT_AMD64 = 0x100000

	CONTEXT_CONTROL         = (CONTEXT_AMD64 | 0x1)
	CONTEXT_INTEGER         = (CONTEXT_AMD64 | 0x2)
	CONTEXT_SEGMENTS        = (CONTEXT_AMD64 | 0x4)
	CONTEXT_FLOATING_POINT  = (CONTEXT_AMD64 | 0x8)
	CONTEXT_DEBUG_REGISTERS = (CONTEXT_AMD64 | 0x10)

	CONTEXT_FULL = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_FLOATING_POINT)
	CONTEXT_ALL  = (CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS | CONTEXT_FLOATING_POINT | CONTEXT_DEBUG_REGISTERS)

	CONTEXT_EXCEPTION_ACTIVE    = 0x8000000
	CONTEXT_SERVICE_ACTIVE      = 0x10000000
	CONTEXT_EXCEPTION_REQUEST   = 0x40000000
	CONTEXT_EXCEPTION_REPORTING = 0x80000000
)

type WORD uint16
type DWORD64 uint64
type DWORD uint32
type CONTEXT struct {
	P1Home               DWORD64
	P2Home               DWORD64
	P3Home               DWORD64
	P4Home               DWORD64
	P5Home               DWORD64
	P6Home               DWORD64
	ContextFlags         DWORD
	MxCsr                DWORD
	SegCs                WORD
	SegDs                WORD
	SegEs                WORD
	SegFs                WORD
	SegGs                WORD
	SegSs                WORD
	EFlags               DWORD
	Dr0                  DWORD64
	Dr1                  DWORD64
	Dr2                  DWORD64
	Dr3                  DWORD64
	Dr6                  DWORD64
	Dr7                  DWORD64
	Rax                  DWORD64
	Rcx                  DWORD64
	Rdx                  DWORD64
	Rbx                  DWORD64
	Rsp                  DWORD64
	Rbp                  DWORD64
	Rsi                  DWORD64
	Rdi                  DWORD64
	R8                   DWORD64
	R9                   DWORD64
	R10                  DWORD64
	R11                  DWORD64
	R12                  DWORD64
	R13                  DWORD64
	R14                  DWORD64
	R15                  DWORD64
	Rip                  DWORD64
	FloatSave            XMM_SAVE_AREA32 // Is a union normaly I kept only the biggest struct in it since it is supposed to work
	VectorRegister       [26]M128A
	VectorControl        DWORD64
	DebugControl         DWORD64
	LastBranchToRip      DWORD64
	LastBranchFromRip    DWORD64
	LastExceptionToRip   DWORD64
	LastExceptionFromRip DWORD64
}

type XMM_SAVE_AREA32 struct {
	ControlWord    WORD
	StatusWord     WORD
	TagWord        BYTE
	Reserved1      BYTE
	ErrorOpcode    WORD
	ErrorOffset    DWORD
	ErrorSelector  WORD
	Reserved2      WORD
	DataOffset     DWORD
	DataSelector   WORD
	Reserved3      WORD
	MxCsr          DWORD
	MxCsr_Mask     DWORD
	FloatRegisters [8]M128A
	XmmRegisters   [16]M128A
	Reserved4      [96]BYTE
}

type LONGLONG int64
type ULONGLONG uint64
type M128A struct {
	Low  ULONGLONG
	High LONGLONG
}

type BYTE byte
