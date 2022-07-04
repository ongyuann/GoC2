//go:build darwin || linux
// +build darwin linux

package exectools

func WmiExec(args []string) (string, error) {
	return "Not Available.", nil
}
