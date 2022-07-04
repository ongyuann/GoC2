//go:build darwin
// +build darwin

package basic

func ListProcesses() (string, error) {
	// the problem is macos doesnt have /proc
	return "macos shit", nil
}
