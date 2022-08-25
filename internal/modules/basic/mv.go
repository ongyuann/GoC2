//go:build darwin
// +build darwin

package basic

import (
	"fmt"
)

func MoveFile(args []string) (string, error) {
	return fmt.Sprintf("linux"), nil
}
