//go:build darwin || linux
// +build darwin linux

package runbinary

func RunBinary(binaryPath []string) (string, error) {
	return "Need to use execve", nil
}
