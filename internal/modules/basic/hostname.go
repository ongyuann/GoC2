package basic

import "os"

func Hostname() string {
	n, err := os.Hostname()
	if err != nil {
		return "Error"
	}
	return n
}
