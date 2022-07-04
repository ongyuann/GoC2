//go:build darwin || linux
// +build darwin linux

package stealtoken

func StealProcessToken(pidStr string) (string, error) {
	return "Not available on this platform", nil
}
