//go:build windows
// +build windows

package rev2self

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func Rev2Self() (string, error) {
	windows.RevertToSelf()
	var bufferSz uint32 = 255
	buffer := make([]uint16, bufferSz)
	err := windows.GetUserNameEx(2, &buffer[0], &bufferSz)
	if err != nil {
		return "", err
	}
	originalUser := windows.UTF16ToString(buffer)
	return fmt.Sprintf("Reverted To %s", originalUser), nil
}
