package basic

import (
	"fmt"
	"net"
)

func ReverseLookup(ip string) (string, error) {
	ips, err := net.LookupAddr(ip)
	var results string
	if err != nil {
		return "", fmt.Errorf("Could not get IPs: %v\n", err)
	}
	for _, ipa := range ips {
		results += fmt.Sprintf("%s\n", ipa)
	}
	return results, nil
}
