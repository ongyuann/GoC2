//go:build darwin || linux
// +build darwin linux

package goup

import (
	"errors"
)

func AllChecks() (results string, err error) {
	return results, errors.New("Not Available on this platform.")
}
