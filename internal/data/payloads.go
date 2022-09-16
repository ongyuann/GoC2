package data

type DonutPayload struct {
	RawPEBytes  []byte // IN
	FileType    string // .exe .dll
	DonutString string // IN
	ConvertedPE []byte // OUT
}

type SRDIPayload struct {
	RawDllBytes     []byte `json:"raw_dll_bytes"`     // IN
	DllFunctionName string `json:"exported_function"` // IN
	ConvertedDll    []byte `json:"converted_dll"`     // OUT
}
