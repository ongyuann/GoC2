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
	// forward traffic.
	go func() {
		nBytes, err := io.Copy(destinationConn, incoming)
		if err != nil {
			incoming.Close()
			destinationConn.Close()
			pivotConn.StopChan <- true
			return
		}
		if nBytes > 0 {
		}

	}()
	go func() {
		nBytes, err := io.Copy(incoming, destinationConn)
		if err != nil {
		}
		if nBytes > 0 {
		}
	}()
	<-pivotConn.StopChan
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
	// forward traffic.
	go func() {
		nBytes, err := io.Copy(destinationConn, incoming)
		if err != nil {
			incoming.Close()
			//destinationConn.Close()
			p.SrcConns[max-1].StopChan <- true
			return
		}
		if nBytes > 0 {
		}
	}()
	go func() {
		// check if connection is open
		// copy bytes
		nBytes, err := io.Copy(incoming, destinationConn)
		if err != nil {
			destinationConn.Close()
			p.SrcConns[max-1].StopChan <- true
			return
		}
		if nBytes > 0 {
		}
	}()
	<-p.SrcConns[max-1].StopChan
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
		HttpPivotGlobal.StopPivotListener()
		HttpPivotGlobal.ShutDown = true
	}()
	for {
		if HttpPivotGlobal.ShutDown {
			break
		}
		incoming, err := HttpPivotGlobal.Listener.Accept()
		if err != nil {
			continue
		}
		go HttpPivotGlobal.HandleNewHTTPConnections(incoming)
	}
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
