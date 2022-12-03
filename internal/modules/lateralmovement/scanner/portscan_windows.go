//go:build windows
// +build windows

package scanner

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

var CommonPorts []int = []int{21, 22, 25, 80, 443, 135, 139, 389, 636, 3389, 445, 5985, 5986, 9389, 9389}

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

func DoCommonPortsToSeeIfHostUp(address string) bool {
	//results := ""
	//fmt.Println("started worker")
	for _, port := range CommonPorts {
		target := fmt.Sprintf("%s:%d", address, port)
		conn, err := net.DialTimeout("tcp", target, time.Second*1)
		if err != nil {
			continue
		}
		if err == nil {
			conn.Close()
			//results += fmt.Sprintf("[+] %s TCP PORT %d OPEN", target, port)
			return true
		}
	}
	//fmt.Println("ended worker")
	return false
}

func MultiplePortScan(target string) (string, error) {
	var wg sync.WaitGroup
	results := ""
	// scan top 10000 tcp ports
	for _, port := range CommonPorts {
		p := port
		wg.Add(1)
		go func() {
			defer wg.Done()
			targetPort := fmt.Sprintf("%s:%d", target, p)
			conn, err := net.DialTimeout("tcp", targetPort, time.Second*10)
			if err == nil {
				conn.Close()
				results += fmt.Sprintf("[+] %s TCP PORT %d OPEN\n", target, p)
			}
			return
		}()
	}
	wg.Wait()
	return results, nil
}

func SubnetScan(subnet string) (string, error) {
	var wg sync.WaitGroup
	split := strings.Split(subnet, ".")
	if len(split) != 4 {
		return "", errors.New("IP Format must be x.x.x.x")
	}
	results := ""
	addressNice := strings.Join(split[0:len(split)-1], ".")
	for x := 0; x < 255; x++ {
		y := x
		wg.Add(1)
		go func() {
			target := fmt.Sprintf("%s.%d", addressNice, y)
			defer wg.Done()
			up := DoCommonPortsToSeeIfHostUp(target)
			if up {
				results += fmt.Sprintf(" - %s Reachable\n", target)
			}
		}()
	}
	wg.Wait()
	return results, nil
}
