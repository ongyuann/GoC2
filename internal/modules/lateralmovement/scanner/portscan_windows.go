//go:build windows
// +build windows

package scanner

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/latortuga71/GoC2/pkg/winapi"
)

func SinglePortScan(args []string) (string, error) {
	if len(args) < 2 {
		return "", errors.New("Not Enough Args")
	}
	host := args[0]
	port := args[1]
	target := fmt.Sprintf("%s:%s", host, port)
	conn, err := net.Dial("tcp", target)
	if err != nil {
		return fmt.Sprintf("[-] TCP PORT %s CLOSED\n", port), nil

	}
	defer conn.Close()
	return fmt.Sprintf("[+] TCP PORT %s OPEN\n", port), nil
}

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
