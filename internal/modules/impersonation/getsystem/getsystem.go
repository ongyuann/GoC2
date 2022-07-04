//go:build darwin || linux
// +build darwin linux

package getsystem

func GetSystem() (string, error) {
	return "Not available on this platform.", nil
}
