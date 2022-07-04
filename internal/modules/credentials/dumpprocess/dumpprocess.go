//go:build darwin || linux
// +build darwin linux

package dumpprocess

func MiniDumpProcess(pid []string) (string, error) {
	return "Linux/Mac Process Dump?", nil
}
