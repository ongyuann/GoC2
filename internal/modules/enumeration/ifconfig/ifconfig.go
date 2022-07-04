package ifconfig

import (
	"fmt"
	"net"
)

// Taken from merlin
//https://github.com/Ne0nd0g/merlin-agent/blob/dev/commands/ifconfig.go

func Ifconfig() (stdout string, err error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, i := range ifaces {
		stdout += fmt.Sprintf("%s\n", i.Name)
		stdout += fmt.Sprintf("  MAC Address\t%s\n", i.HardwareAddr.String())
		addrs, err := i.Addrs()
		if err != nil {
			return "", err
		}
		for _, a := range addrs {
			stdout += fmt.Sprintf("  IP Address\t%s\n", a.String())
		}
	}
	return stdout, nil
}
