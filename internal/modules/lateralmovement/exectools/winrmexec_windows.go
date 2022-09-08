package exectools

import (
	"fmt"
	"time"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

// globals
var hEvent uintptr
var hReceiveEvent uintptr
var results string

func init() {
	results = ""
}

func ResetResults() {
	results = ""
}

func ReadBuffer(start *byte, length uint32) []byte {
	buff := make([]byte, length)
	for x := 0; uint32(x) < length; x++ {
		buff[x] = *start
		start = (*byte)(unsafe.Pointer(uintptr(unsafe.Pointer(start)) + 1))
	}
	return buff
}

func RecvCallback(operationContext uintptr, flags uint32, err *winapi.WSMAN_ERROR, shell winapi.WSMAN_SHELL_HANDLE, commandHandle winapi.WSMAN_COMMAND_HANDLE, operationHandle winapi.WSMAN_OPERATION_HANDLE, data *winapi.WSMAN_RECEIVE_DATA_RESULT) uintptr {
	//fmt.Println("recv callback")
	//fmt.Println("recv event", hReceiveEvent)
	var e error
	if err != nil && err.Code != 0 {
		errorStr := windows.UTF16PtrToString(err.ErrorDetail)
		results += fmt.Sprintf("Receive Callback Error -> %s\n", errorStr)
		return 0
	}
	if data != nil && data.StreamData.Type == winapi.WSMAN_DATA_TYPE_BINARY && data.StreamData.BinaryData.DataLength > 0 {
		buff := ReadBuffer(data.StreamData.BinaryData.Data, data.StreamData.BinaryData.DataLength)
		results += string(buff)
		return 0
	}
	if (err != nil && err.Code != 0) || (data != nil) {
		state := windows.UTF16PtrToString(data.CommandState)
		if state == "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done" {
			e = winapi.SetEvent(hReceiveEvent)
			if e != nil {
				results += fmt.Sprintf("Shell Callback Error -> %s\n", e)
			}
			//fmt.Println("recv event set")
		}
	}
	return 0
}

func ShellCallback(operationContext uintptr, flags uint32, err *winapi.WSMAN_ERROR, shell winapi.WSMAN_SHELL_HANDLE, commandHandle winapi.WSMAN_COMMAND_HANDLE, operationHandle winapi.WSMAN_OPERATION_HANDLE, data *winapi.WSMAN_RECEIVE_DATA_RESULT) uintptr {
	//fmt.Println("shell callback")
	//fmt.Println("shell event", hEvent)
	if err.Code != 0 {
		errorStr := windows.UTF16PtrToString(err.ErrorDetail)
		if errorStr != `The WinRM Shell client cannot process the request. The shell handle passed to the WSMan Shell function is not valid. The shell handle is valid only when WSManCreateShell function completes successfully. Change the request including a valid shell handle and try again.` {
			results += fmt.Sprintf("%s\n", errorStr)
		}
	}
	e := winapi.SetEvent(hEvent)
	if e != nil {
		results += fmt.Sprintf("Shell Callback Error -> %s\n", e)
	}
	//fmt.Println("shell event set")
	return 0
}

func WinRmExec(args []string) (string, error) {
	/*log.Println(args)
	results, err := WinRmExecuteCommand("HACKERLAB", "turtleadmin", "dawoof7123!!!", "dc01", "5985", "hostname")
	if err != nil {
		return "", fmt.Errorf("%s %s", results, err)
	}
	return results, nil
	*/
	// domain user pass host port command ssl
	if len(args) < 7 {
		return "", fmt.Errorf("Not Enough Args")
	}
	if args[6] == "true" || args[6] == "1" {
		results, err := WinRmExecuteCommandSSL(args[0], args[1], args[2], args[3], args[4], args[5])
		if err != nil {
			return "", fmt.Errorf("%s %s", results, err)
		}
		return results, nil
	}
	results, err := WinRmExecuteCommand(args[0], args[1], args[2], args[3], args[4], args[5])
	if err != nil {
		return "", fmt.Errorf("%s %s", results, err)
	}
	return results, nil
}

func WinRmExecuteCommand(domain, user, pass, host, port, command string) (string, error) {
	var clientHandle uintptr
	err := winapi.WSManInitialize(winapi.WSMAN_FLAG_REQUESTED_API_VERSION_1_0, &clientHandle)
	if err != nil {
		return results, err
	}
	authCreds := winapi.WSMAN_AUTHENTICATION_CREDENTIALS{}
	authCreds.UserAccount = winapi.WSMAN_USERNAME_PASSWORD_CREDS{}
	username, err := windows.UTF16PtrFromString(fmt.Sprintf("%s\\%s", domain, user))
	if err != nil {
		return results, err
	}
	password, err := windows.UTF16PtrFromString(pass)
	if err != nil {
		return results, err
	}
	authCreds.UserAccount.Username = username
	authCreds.UserAccount.Password = password
	// if no domain is supplied we need to use basic NTLM auth
	// else we can try kerberose then fallback to NTLM
	if domain == "" || domain == "." {
		authCreds.AuthenticationMechanism = winapi.WSMAN_FLAG_AUTH_BASIC
		username, err = windows.UTF16PtrFromString(fmt.Sprintf("%s", user))
		if err != nil {
			return results, err
		}
		authCreds.UserAccount.Username = username
	} else {
		authCreds.AuthenticationMechanism = winapi.WSMAN_FLAG_AUTH_NEGOTIATE
	}
	var session winapi.WSMAN_SESSION_HANDLE
	//log.Println("before create session")
	shellCall := windows.NewCallback(ShellCallback)
	recvCall := windows.NewCallback(RecvCallback)
	async := winapi.WSMAN_SHELL_ASYNC{}
	async.CompletionFunction = shellCall
	recvAsync := winapi.WSMAN_SHELL_ASYNC{}
	recvAsync.CompletionFunction = recvCall
	var shell winapi.WSMAN_SHELL_HANDLE
	err = winapi.WSManCreateSession(winapi.WSMAN_API_HANDLE(clientHandle), fmt.Sprintf("http://%s:%s", host, port), 0, &authCreds, 0, &session)
	if err != nil {
		Cleanup(clientHandle, 0, 0, 0, session, &async)
		return results, err
	}
	//log.Println("after create session")
	hEvent, err = winapi.CreateEventW(nil, 0, 0, "")
	if err != nil {
		Cleanup(clientHandle, 0, 0, 0, session, &async)
		return results, err
	}
	hReceiveEvent, err = winapi.CreateEventW(nil, 0, 0, "")
	if err != nil {
		Cleanup(clientHandle, 0, 0, 0, session, &async)
		return results, err
	}
	//log.Println("before create shell")
	err = winapi.WSManCreateShell(session, 0, winapi.WSMAN_CMDSHELL_URI, 0, 0, 0, &async, &shell)
	if err != nil {
		Cleanup(clientHandle, 0, 0, 0, session, &async)
		return results, err
	}
	//log.Println("after create shell")
	windows.WaitForSingleObject(windows.Handle(hEvent), windows.INFINITE)
	//log.Println("after shell wait")
	var cmdHandle winapi.WSMAN_COMMAND_HANDLE
	//log.Println("before run command")
	err = winapi.WSManRunShellCommand(shell, 0, command, 0, 0, &async, &cmdHandle)
	if err != nil {
		Cleanup(clientHandle, 0, 0, shell, session, &async)
		return results, err
	}
	//log.Println("after run command")
	windows.WaitForSingleObject(windows.Handle(hEvent), windows.INFINITE)
	//log.Println("after command wait")
	var opHandle winapi.WSMAN_OPERATION_HANDLE
	//log.Println("before recv out ")
	err = winapi.WSManReceiveShellOutput(shell, cmdHandle, 0, 0, &recvAsync, &opHandle)
	if err != nil {
		Cleanup(clientHandle, 0, cmdHandle, shell, session, &async)
		return results, err
	}
	//log.Println("after recv out ")
	windows.WaitForSingleObject(windows.Handle(hReceiveEvent), windows.INFINITE)
	go func() {
		time.Sleep(time.Second * 10)
		//log.Println("before clean")
		Cleanup(clientHandle, opHandle, cmdHandle, shell, session, &async)
	}()
	return results, nil
}

func Cleanup(clientHandle uintptr, opHandle winapi.WSMAN_OPERATION_HANDLE, cmdHandle winapi.WSMAN_COMMAND_HANDLE, shell winapi.WSMAN_SHELL_HANDLE, session winapi.WSMAN_SESSION_HANDLE, async *winapi.WSMAN_SHELL_ASYNC) {
	//log.Println("cleaning")
	if opHandle != 0 {
		winapi.WSManCloseOperation(opHandle, 0)
		//log.Println("cleaned op handle")
	}
	if cmdHandle != 0 {
		//log.Println("cmd", cmdHandle)
		winapi.WSManCloseCommand(cmdHandle, 0, async)
		windows.WaitForSingleObject(windows.Handle(hEvent), windows.INFINITE)
		//log.Println("cleaned cmdHandle")
	}
	if shell != 0 {
		//log.Println("shell")
		winapi.WSManCloseShell(shell, 0, async)
		windows.WaitForSingleObject(windows.Handle(hEvent), windows.INFINITE)
		//log.Println("cleaned shell handle")
	}
	if session != 0 {
		//log.Println("session")
		winapi.WSManCloseSession(session, 0)
		//log.Println("cleaned session handle")
	}
	if clientHandle != 0 {
		//log.Println("client")
		winapi.WSManDeinitialize(winapi.WSMAN_API_HANDLE(clientHandle), 0)
		//log.Println("cleaned client handle")
	}
	windows.CloseHandle(windows.Handle(hReceiveEvent))
	windows.CloseHandle(windows.Handle(hEvent))
}

func WinRmExecuteCommandSSL(domain, user, pass, host, port, command string) (string, error) {
	var clientHandle uintptr
	err := winapi.WSManInitialize(winapi.WSMAN_FLAG_REQUESTED_API_VERSION_1_0, &clientHandle)
	if err != nil {
		return results, err
	}
	authCreds := winapi.WSMAN_AUTHENTICATION_CREDENTIALS{}
	authCreds.UserAccount = winapi.WSMAN_USERNAME_PASSWORD_CREDS{}
	username, err := windows.UTF16PtrFromString(fmt.Sprintf("%s\\%s", domain, user))
	if err != nil {
		return results, err
	}
	password, err := windows.UTF16PtrFromString(pass)
	if err != nil {
		return results, err
	}
	authCreds.UserAccount.Username = username
	authCreds.UserAccount.Password = password
	// if no domain is supplied we need to use basic NTLM auth
	// else we can try kerberose then fallback to NTLM
	if domain == "" || domain == "." {
		authCreds.AuthenticationMechanism = winapi.WSMAN_FLAG_AUTH_BASIC
	} else {
		authCreds.AuthenticationMechanism = winapi.WSMAN_FLAG_AUTH_NEGOTIATE
	}
	var session winapi.WSMAN_SESSION_HANDLE
	//log.Println("before create session")
	shellCall := windows.NewCallback(ShellCallback)
	recvCall := windows.NewCallback(RecvCallback)
	async := winapi.WSMAN_SHELL_ASYNC{}
	async.CompletionFunction = shellCall
	recvAsync := winapi.WSMAN_SHELL_ASYNC{}
	recvAsync.CompletionFunction = recvCall
	var shell winapi.WSMAN_SHELL_HANDLE
	err = winapi.WSManCreateSession(winapi.WSMAN_API_HANDLE(clientHandle), fmt.Sprintf("https://%s:%s", host, port), 0, &authCreds, 0, &session)
	if err != nil {
		Cleanup(clientHandle, 0, 0, 0, session, &async)
		return results, err
	}
	//log.Println("after create session")
	hEvent, err = winapi.CreateEventW(nil, 0, 0, "")
	if err != nil {
		Cleanup(clientHandle, 0, 0, 0, session, &async)
		return results, err
	}
	hReceiveEvent, err = winapi.CreateEventW(nil, 0, 0, "")
	if err != nil {
		Cleanup(clientHandle, 0, 0, 0, session, &async)
		return results, err
	}
	//log.Println("before create shell")
	err = winapi.WSManCreateShell(session, 0, winapi.WSMAN_CMDSHELL_URI, 0, 0, 0, &async, &shell)
	if err != nil {
		Cleanup(clientHandle, 0, 0, 0, session, &async)
		return results, err
	}
	//log.Println("after create shell")
	windows.WaitForSingleObject(windows.Handle(hEvent), windows.INFINITE)
	//log.Println("after shell wait")
	var cmdHandle winapi.WSMAN_COMMAND_HANDLE
	//log.Println("before run command")
	err = winapi.WSManRunShellCommand(shell, 0, command, 0, 0, &async, &cmdHandle)
	if err != nil {
		Cleanup(clientHandle, 0, 0, shell, session, &async)
		return results, err
	}
	//log.Println("after run command")
	windows.WaitForSingleObject(windows.Handle(hEvent), windows.INFINITE)
	//log.Println("after command wait")
	var opHandle winapi.WSMAN_OPERATION_HANDLE
	//log.Println("before recv out ")
	err = winapi.WSManReceiveShellOutput(shell, cmdHandle, 0, 0, &recvAsync, &opHandle)
	if err != nil {
		Cleanup(clientHandle, 0, cmdHandle, shell, session, &async)
		return results, err
	}
	//log.Println("after recv out ")
	windows.WaitForSingleObject(windows.Handle(hReceiveEvent), windows.INFINITE)
	go func() {
		time.Sleep(time.Second * 10)
		//log.Println("before clean")
		Cleanup(clientHandle, opHandle, cmdHandle, shell, session, &async)
	}()
	return results, nil
}
