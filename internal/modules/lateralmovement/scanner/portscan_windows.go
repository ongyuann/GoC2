//go:build windows
// +build windows

package scanner

import (
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/latortuga71/wsC2/pkg/winapi"
)

func SubnetScan(subnet string) (string, error) {
	//this takes a couple minutes
	split := strings.Split(subnet, ".")
	if len(split) != 4 {
		return "", errors.New("IP Format must be x.x.x.x")
	}
	results := ""
	addressNice := strings.Join(split[0:len(split)-1], ".")
	for x := 0; x < 255; x++ {
		target := fmt.Sprintf("%s.%d", addressNice, x)
		ok := winapi.GetRTTAndHopCount(target)
		if !ok {
			results += fmt.Sprintf("[-] %s Unreachable\n", target)
			continue
		}
		results += fmt.Sprintf("[+] %s Reachable\n", target)
	}
	return results, nil
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
