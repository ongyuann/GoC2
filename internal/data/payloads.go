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

type LoaderPayload struct {
	RawShellcodeBytes []byte `json:"raw_shellcode_bytes"`
	LoaderType        string `json:"loader_type"` // powershell, jscript, vbscript etc.
	LoaderStringB64   string `json:"loader_string"`
	LoaderString      string `json:"loader_string_encoded"`
}
