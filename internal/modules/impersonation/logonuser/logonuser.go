//go:build darwin || linux
// +build darwin linux

package logonuser

func RunAs(args []string) (string, error) {
	return "Need to implement on linux setuid", nil
}

func RunAsNetOnly(args []string) (string, error) {
	return "Not Available On This Platform.", nil
}
