//go:build darwin || linux
// +build darwin linux

package shellhistory

import (
	"fmt"
	"os"
	"strings"
)

func GetShellHistory() (string, error) {
	//historyFiles := make([]string, 0)
	results := "[+] Shell History Files\n"
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	d, err := os.ReadDir(home)
	if err != nil {
		return "", err
	}
	for _, x := range d {
		if x.IsDir() {
			continue
		}
		if strings.Contains(x.Name(), "_history") {
			results += fmt.Sprintf("[+] %s/%s\n", home, x.Name())
		}
	}
	return results, nil
}
