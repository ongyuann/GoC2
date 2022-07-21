//go:build darwin
// +build darwin

package listports

func ListPorts() (string, error) {
	return "sysctl??", nil
}
