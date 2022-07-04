//go:build darwin || linux
// +build darwin linux

package listservices

func ListServices() (string, error) {
	return "Need to implement listing daemons?", nil
}
