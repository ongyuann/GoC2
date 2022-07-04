package basic

import "os"

func PrintWorkingDirectory() (string, error) {
	return os.Getwd()
}
