package enumdrivers

import "github.com/latortuga71/GoC2/pkg/winapi"

func EnumerateDrivers() (string, error) {
	return winapi.EnumDeviceDrivers()
}
