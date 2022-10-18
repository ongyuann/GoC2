package pivot

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
)

type ClientPivotConnection struct {
	StopChan chan bool
	Conn     net.Conn
}

type PivotConnections struct {
	sync.Mutex
	ListenerAddr string // pivot listener ip and port
	Listener     net.Listener
	SrcConns     []*ClientPivotConnection
	DestAddr     string // C2 ip and port
	DestConns    []net.Conn
	PivotError   error
	ShuttingDown chan bool
	ShutDown     bool
}

func NewClientPivotConnection() *ClientPivotConnection {
	return &ClientPivotConnection{
		StopChan: make(chan bool),
		Conn:     nil,
	}
}

func NewPivotConnections(listenerAddr string, destAddr string) *PivotConnections {
	return &PivotConnections{
		ListenerAddr: listenerAddr,
		Listener:     nil,
		SrcConns:     make([]*ClientPivotConnection, 0),
		DestAddr:     destAddr,
		DestConns:    make([]net.Conn, 0),
		PivotError:   nil,
		ShuttingDown: make(chan bool),
		ShutDown:     false,
	}
}

func (p *PivotConnections) StartPivotListener() (string, error) {
	p.Listener, p.PivotError = net.Listen("tcp", p.ListenerAddr)
	if p.PivotError != nil {
		return "", p.PivotError
	}
	fmt.Printf("Listening on %s\n", p.ListenerAddr)
	return "", nil
}

// this blocks so run in goroutine
func (p *PivotConnections) HandleNewHTTPConnections(incoming net.Conn) error {
	pivotConn := NewClientPivotConnection()
	// open connection to dest
	destinationConn, err := net.Dial("tcp", p.DestAddr)
	if err != nil {
		return err
	}
	fmt.Printf("Connected to dest %s\n", p.DestAddr)
	// forward traffic.
	go func() {
		nBytes, err := io.Copy(destinationConn, incoming)
		if err != nil {
			fmt.Printf("CLIENT ERR %v\n", err)
			incoming.Close()
			destinationConn.Close()
			pivotConn.StopChan <- true
			return
		}
		if nBytes > 0 {
			fmt.Printf("Transferred %d bytes\n", nBytes)
		}

	}()
	go func() {
		nBytes, err := io.Copy(incoming, destinationConn)
		if err != nil {
			fmt.Printf("SERVER ERRR %v\n", err)
		}
		if nBytes > 0 {
			fmt.Printf("Transferred %d bytes\n", nBytes)
		}
	}()
	fmt.Printf("Blocking here to forward traffic consistently.\n")
	<-pivotConn.StopChan
	fmt.Println("Connections Died Cleaning Up.")
	return nil
}

// this blocks so run in goroutine
func (p *PivotConnections) HandleNewWSConnections(incoming net.Conn) error {
	pivotConn := NewClientPivotConnection()
	pivotConn.Conn = incoming
	p.Lock()
	p.SrcConns = append(p.SrcConns, pivotConn)
	p.Unlock()
	// open connection to dest
	destinationConn, err := net.Dial("tcp", p.DestAddr)
	if err != nil {
		return err
	}
	p.Lock()
	p.DestConns = append(p.DestConns, destinationConn)
	p.Unlock()
	max := len(p.SrcConns)
	max2 := len(p.DestConns)
	fmt.Printf("Connected to dest %s\n", p.DestAddr)
	// forward traffic.
	go func() {
		nBytes, err := io.Copy(destinationConn, incoming)
		if err != nil {
			fmt.Printf("CLIENT ERR %v\n", err)
			incoming.Close()
			//destinationConn.Close()
			p.SrcConns[max-1].StopChan <- true
			return
		}
		if nBytes > 0 {
			fmt.Printf("Transferred %d bytes\n", nBytes)
		}
	}()
	go func() {
		// check if connection is open
		// copy bytes
		nBytes, err := io.Copy(incoming, destinationConn)
		if err != nil {
			fmt.Printf("SERVER ERRR %v\n", err)
			destinationConn.Close()
			p.SrcConns[max-1].StopChan <- true
			return
		}
		if nBytes > 0 {
			fmt.Printf("Transferred %d bytes\n", nBytes)
		}
	}()
	fmt.Printf("Currently %d client connections\n", max)
	fmt.Printf("Currently %d c2 connections\n", max2)
	fmt.Printf("Blocking here to forward traffic consistently.\n")
	<-p.SrcConns[max-1].StopChan
	fmt.Println("Shutting down pivot..")
	return nil
}

func (p *PivotConnections) StopPivotListener() error {
	for _, c := range p.SrcConns {
		c.StopChan <- true
	}
	for _, c := range p.DestConns {
		c.Close()
	}
	for _, c := range p.SrcConns {
		c.Conn.Close()
	}
	p.Listener.Close()
	return nil
}

var HttpPivotGlobal *PivotConnections
var WSPivotGlobal *PivotConnections

func StopHTTPPivot() {
	HttpPivotGlobal.ShuttingDown <- true
}

func StopWSPivot() {
	WSPivotGlobal.ShuttingDown <- true
}

func HTTPPivot(listenerAddr, destinationAddr string) {
	HttpPivotGlobal = NewPivotConnections(listenerAddr, destinationAddr)
	_, err := HttpPivotGlobal.StartPivotListener()
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		<-HttpPivotGlobal.ShuttingDown
		fmt.Println("\nReceived an interrupt, stopping...")
		HttpPivotGlobal.StopPivotListener()
		HttpPivotGlobal.ShutDown = true
	}()
	for {
		if HttpPivotGlobal.ShutDown {
			break
		}
		incoming, err := HttpPivotGlobal.Listener.Accept()
		if err != nil {
			fmt.Printf("Failed to accept connection???\n")
			continue
		}
		go HttpPivotGlobal.HandleNewHTTPConnections(incoming)
	}
	fmt.Printf("HTTP Pivot Server completely shutdown!\n")
}

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
