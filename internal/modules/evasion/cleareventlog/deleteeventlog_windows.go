//go:build windows
// +build windows

package cleareventlog

import (
	"fmt"

	"github.com/latortuga71/GoC2/pkg/winapi"
)

func DeleteEventLog(logname string) (string, error) {
	l, err := winapi.OpenEventLogW("", logname)
	if l == 0 {
		return "", err
	}
	defer winapi.CloseEventLog(l)
	res, err := winapi.ClearEventLogW(l, "")
	if !res {
		return "", err
	}
	return fmt.Sprintf("Successfully Deleted %s Event Log", logname), nil
}
