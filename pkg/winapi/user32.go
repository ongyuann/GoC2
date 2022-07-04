package winapi

import "syscall"

var (
	pModUser32           = syscall.NewLazyDLL("user32.dll")
	pGetDesktopWindow    = pModUser32.NewProc("GetDesktopWindow")
	pGetWindowRect       = pModUser32.NewProc("GetWindowRect")
	pEnumDisplayMonitors = pModUser32.NewProc("EnumDisplayMonitors")
	pGetMonitorInfo      = pModUser32.NewProc("GetMonitorInfoW")
	pEnumDisplaySettings = pModUser32.NewProc("EnumDisplaySettingsW")
	pEnumChildWindows    = pModUser32.NewProc("EnumChildWindows")
)
