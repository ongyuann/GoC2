package winapi

import "syscall"

var (
	pModWevtapi32 = syscall.NewLazyDLL("Wevtapi.dll")
	pEvtClearLog  = pModWevtapi32.NewProc("EvtClearLog")
)
