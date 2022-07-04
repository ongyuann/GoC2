//go:build darwin || linux
// +build darwin linux

package exectools

func SmbExec(args []string) (string, error) {
	return "Not available.", nil
}
