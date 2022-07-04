package env

import (
	"fmt"
	"os"
)

func PrintEnv() (string, error) {
	resp := "\nEnvironment variables:\n"
	for _, element := range os.Environ() {
		resp += fmt.Sprintf("%s\n", element)
	}

	return resp, nil
}
