package basic

import "net"

func Nslookup(name string) (string, error) {
	var results string
	record, err := net.LookupIP(name)
	if err != nil {
		return "", err
	}
	for _, r := range record {
		results += r.String()
	}
	return results, nil
}
