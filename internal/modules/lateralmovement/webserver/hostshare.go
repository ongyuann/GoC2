package webserver

import (
	"context"
	"fmt"
	"net/http"
	"time"
)

var StopChan chan bool = make(chan bool)
var ServerRunning bool
var ListeningPort string

func StopWebServer() (string, error) {
	StopChan <- true
	<-StopChan
	ListeningPort = ""
	ServerRunning = false
	return "[+] Stopped WebServer", nil
}

func StartWebServer(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("not enough args")
	}
	webRoot := args[0]
	ListeningPort = args[1]
	if ServerRunning == true {
		return fmt.Sprintf("Server Already Running On %s", ListeningPort), nil
	}
	m := http.NewServeMux()
	fs := http.FileServer(http.Dir(webRoot))
	m.Handle("/", fs)
	s := http.Server{Addr: ListeningPort, Handler: m}
	go func() {
		var err error
		<-StopChan
		// shutdown server
		ctxShutDown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer func() {
			cancel()
		}()
		if err = s.Shutdown(ctxShutDown); err != nil {
			//fmt.Println("shutdown with errs")
			StopChan <- true
		} else {
			//fmt.Println("shutdown no errs")
			StopChan <- true
		}
	}()
	go func() {
		ServerRunning = true
		if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			//fmt.Println("SERVER SHUTDOWN WITH ERRORS")
			ServerRunning = false
		} else {
			//fmt.Println("SERVER SHUTDOWN.")
			ServerRunning = false
		}
	}()
	return fmt.Sprintf("[+] Started WebServer On %s", ListeningPort), nil
}

/*
func WSPivot(listenerAddr, destinationAddr string) {
	WSPivotGlobal = NewPivotConnections(listenerAddr, destinationAddr)
	_, err := WSPivotGlobal.StartPivotListener()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		<-WSPivotGlobal.ShuttingDown
		fmt.Println("\nReceived an interrupt, stopping...")
		//WSPivotGlobal.StopPivotListener()
		WSPivotGlobal.ShutDown = true
	}()
	for {
		if WSPivotGlobal.ShutDown {
			break
		}
		incoming, err := WSPivotGlobal.Listener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept connection???\n")
			continue
		}
		go WSPivotGlobal.HandleNewWSConnections(incoming)
	}
	fmt.Printf("WS Pivot Server completely shutdown!\n")
}
*/
/*
func ShareDirectory() (string, error) {
	var shareBuffer winapi.SHARE_INFO_2
	path, err := windows.UTF16PtrFromString(`C:\\ExampleShare`)
	if err != nil {
		return "", err
	}
	netname, err := windows.UTF16PtrFromString("TESTSHARE")
	if err != nil {
		return "", err
	}
	remark, err := windows.UTF16PtrFromString("REMARK")
	if err != nil {
		return "", err
	}

	shareBuffer.NetName = netListenAndServe()
	shareBuffer.Type = 0x00000000 // disk drive
	shareBuffer.Remark = remark
	shareBuffer.Permissions = 0
	shareBuffer.MaxUses = 4
	shareBuffer.CurrentConections = 0
	shareBuffer.Path = path
	shareBuffer.Password = nil
	err = winapi.NetShareAdd(".", 2, &shareBuffer)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("[+] Sharing %s", "C:\\Webserver"), nil
}
*/
