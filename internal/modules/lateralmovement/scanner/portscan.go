//go:build darwin || linux
// +build darwin linux

package scanner

import (
	"fmt"
	"log"
	"net"
	"time"
)

func SubnetScan(subnet string) (string, error) {
	return "mac/linux raw sockets needs admin.", nil
}

func TcpCheck(host string, port int) (string, error) {
	target := fmt.Sprintf("%s:%d", host, port)
	log.Println(port)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		log.Println(err)
		return "", err
	}
	conn.Close()
	return fmt.Sprintf("TCP PORT %d OPEN\n", port), nil
}

func UdpCheck(host, port string) (string, error) {
	target := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.DialTimeout("udp", target, time.Second*2)
	if err != nil {
		return "", err
	}
	conn.Close()
	return fmt.Sprintf("UDP PORT %s OPEN\n", port), nil
}

func PortScan(ip string) (string, error) {
	results := ""
	for port := 71; port < 90; port++ {
		if res, err := TcpCheck(ip, port); err == nil {
			results += res
		}
	}
	return results, nil
}
