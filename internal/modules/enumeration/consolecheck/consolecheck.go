package consolecheck

import (
	"fmt"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func ConsolCheck() (string, error) {
	var s uint32
	ok := windows.ProcessIdToSessionId(windows.GetCurrentProcessId(), &s)
	if ok != nil {
		return "", ok
	}
	if ok := winapi.GetConsoleWindow(); ok == 0 {
		return fmt.Sprintf("[+] Session is %d No Console Allocated!\n", s), nil
	}
	return fmt.Sprintf("[+] Session is %d Console Is Allocated!\n", s), nil
}
