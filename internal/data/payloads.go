package data

type DonutPayload struct {
	RawPEBytes  []byte `json:"raw_pe_bytes"` // IN
	FileType    string `json:"file_type"`    // .exe .dll
	DonutString string `json:"donut_params"` // IN
	ConvertedPE []byte `json:"converted_pe"` // OUT
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

type ImplantComm string
type ImplantType string

const (
	WsCommunication   ImplantComm = "ws"
	HttpCommunication ImplantComm = "http"
	DllImplant        ImplantType = "dll"
	ExeImplant        ImplantType = "exe"
)

type MalleableClient struct {
	Communication    ImplantComm `json:"implant_comm"`
	Type             ImplantType `json:"implant_type"`
	ServerHostName   string      `json:"server_hostname"`
	ServerPort       string      `json:"server_port"`
	ServerSecret     string      `json:"server_secret"`
	UserAgent        string      `json:"user_agent"`
	GeneratedImplant []byte      `json:"generated_implant"`
	//.... more stufff here in future?
}
