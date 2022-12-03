//go:build darwin || linux
// +build darwin linux

package scanner

import (
	"errors"
	"fmt"
	"net"
	"time"
)

func SubnetScan(subnet string) (string, error) {
	return "mac/linux raw sockets needs admin.", nil
}

func SinglePortScan(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	host := args[0]
	port := args[1]
	results := ""
	target := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		results += fmt.Sprintf("TCP PORT %s CLOSED", port)
	}
	conn.Close()
	results += fmt.Sprintf("TCP PORT %s OPEN\n", port)
	conn, err = net.DialTimeout("udp", target, time.Second*2)
	if err != nil {
		results += fmt.Sprintf("UDP ORT %s CLOSED", port)
	}
	conn.Close()
	results += fmt.Sprintf("UDP PORT %s OPEN\n", port)
	return results, nil
}
