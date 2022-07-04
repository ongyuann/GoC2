//go:build darwin || linux
// +build darwin linux

package services

import (
	"fmt"
)

func FilelessService(args []string) (string, error) {
	return fmt.Sprintf("Not Available On This Platform."), nil
}

func DeleteService(args []string) (string, error) {
	return fmt.Sprintf("Not Available On This Platform."), nil
}

func StartService(args []string) (string, error) {
	return fmt.Sprintf("Not Available On This Platform."), nil
}

func StopService(args []string) (string, error) {
	return fmt.Sprintf("Not Available On This Platform."), nil
}

func CreateService(args []string) (string, error) {
	return fmt.Sprintf("Not Available On This Platform."), nil
}
