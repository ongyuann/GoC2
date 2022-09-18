//go:build darwin || linux
// +build darwin linux

package portforward

func PortForward(args []string) (string, error) {
	return "Implement on linux", nil
}

func RevertPortForward() (string, error) {
	return "Implement on linux", nil
}
