package data

type DonutPayload struct {
	RawPEBytes  []byte // IN
	FileType    string // .exe .dll
	DonutString string // IN
	ConvertedPE []byte // OUT
}

type SRDIPayload struct {
	RawDllBytes     []byte // IN
	DllFunctionName string // IN
	ConvertedDll    []byte // OUT
}
