//go:build darwin || linux
// +build darwin linux

package cleareventlog

import (
	"fmt"
)

func DeleteEventLog(logname string) (string, error) {
	return fmt.Sprintf("Not Available Yet!", logname), nil
}
