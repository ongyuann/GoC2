package winapi

import (
	"syscall"
	"unsafe"
)

var (
	pModUser32           = syscall.NewLazyDLL("user32.dll")
	pGetDesktopWindow    = pModUser32.NewProc("GetDesktopWindow")
	pGetWindowRect       = pModUser32.NewProc("GetWindowRect")
	pEnumDisplayMonitors = pModUser32.NewProc("EnumDisplayMonitors")
	pGetMonitorInfo      = pModUser32.NewProc("GetMonitorInfoW")
	pEnumDisplaySettings = pModUser32.NewProc("EnumDisplaySettingsW")
	pEnumChildWindows    = pModUser32.NewProc("EnumChildWindows")

	pSetWindowsHookExW   = pModUser32.NewProc("SetWindowsHookExW")
	pGetForegroundWindow = pModUser32.NewProc("GetForegroundWindow")
	pGetWindowTextW      = pModUser32.NewProc("GetWindowTextW")
	pCallNextHookEx      = pModUser32.NewProc("CallNextHookEx")
	pUnhookWindowsHookEx = pModUser32.NewProc("UnhookWindowsHookEx")
	pGetMessageW         = pModUser32.NewProc("GetMessageW")
	pDispatchMessageW    = pModUser32.NewProc("DispatchMessageW")
	pLoadCursorW         = pModUser32.NewProc("LoadCursorW")
	pPostQuitMessage     = pModUser32.NewProc("PostQuitMessage")
	pRegisterClassExW    = pModUser32.NewProc("RegisterClassExW")
	pTranslateMessage    = pModUser32.NewProc("TranslateMessage")
	pPostThreadMessageW  = pModUser32.NewProc("PostThreadMessageW")
	pGetKeyBoardState    = pModUser32.NewProc("GetKeyboardState")
	pGetKeyState         = pModUser32.NewProc("GetKeyState")
	pToAscii             = pModUser32.NewProc("ToAscii")
	pGetAsyncKeyState    = pModUser32.NewProc("GetAsyncKeyState")
	HC_ACTION            = 0
	WM_APP               = 0x8000
	WM_KEYDOWN           = 0x0100
	WH_KEYBOARD_LL       = 13
	VK_LSHIFT            = 0xA0
	VK_RSHIFT            = 0xA1
	VK_CAPITAL           = 0x14
	ShiftKey             = 16
	Capital              = 20
)

type POINT struct {
	X, Y int32
}

type MSG struct {
	Hwnd    syscall.Handle
	Message uint32
	WParam  uintptr
	LParam  uintptr
	Time    uint32
	Pt      POINT
}

func GetAsyncKeyState(vKey int) bool {
	short, _, _ := pGetAsyncKeyState.Call(uintptr(vKey))
	if short == 0 {
		return false
	}
	return true
}

func UnhookWindowsHookEx(hHook uintptr) bool {
	success, _, _ := pUnhookWindowsHookEx.Call(hHook)
	if success == 0 {
		return false
	}
	return true
}

func SetWindowsHookExW(idHook int, lpfn uintptr, hmod int, dwThreadId uint32) uintptr {
	handle, _, _ := pSetWindowsHookExW.Call(uintptr(idHook), lpfn, uintptr(hmod), uintptr(dwThreadId))
	if handle == 0 {
		return 0
	}
	return handle
}

func CallNextHookEx(hhook uintptr, code int, wParam uintptr, lParam uintptr) uintptr {
	ret, _, _ := pCallNextHookEx.Call(0, uintptr(code), wParam, lParam)
	return uintptr(ret)
}

func GetWindowText(handle uintptr, buffer uintptr, bufferLen int) bool {
	res, _, _ := pGetWindowTextW.Call(handle, buffer, uintptr(bufferLen))
	if res == 0 {
		return false
	}
	return true
}

func GetForegroundWindow() uintptr {
	handle, _, _ := pGetForegroundWindow.Call()
	if handle == 0 {
		return 0
	}
	return handle
}

func GetMessage(msg *MSG, hwnd syscall.Handle, msgFilterMin, msgFilterMax uint32) (bool, error) {
	ret, _, err := pGetMessageW.Call(
		uintptr(unsafe.Pointer(msg)),
		uintptr(hwnd),
		uintptr(msgFilterMin),
		uintptr(msgFilterMax),
	)
	if int32(ret) == -1 {
		return false, err
	}
	return int32(ret) != 0, nil
}

func PostThreadMessageW(idThread uint32, msg uint32, wParam uintptr, lParam uintptr) bool {
	success, _, _ := pPostThreadMessageW.Call(uintptr(idThread), uintptr(msg), wParam, lParam)
	if success == 0 {
		return false
	}
	return true
}

func PostQuitMessage(exitCode int32) {
	pPostQuitMessage.Call(uintptr(exitCode))
}

func GetModuleHandle() (syscall.Handle, error) {
	ret, _, err := pGetModuleHandleW.Call(uintptr(0))
	if ret == 0 {
		return 0, err
	}
	return syscall.Handle(ret), nil
}
func TranslateMessage(msg *MSG) {
	pTranslateMessage.Call(uintptr(unsafe.Pointer(msg)))
}

func DispatchMessage(msg *MSG) {
	pDispatchMessageW.Call(uintptr(unsafe.Pointer(msg)))
}

func ToAscii(uVirtKey, uScanCode uint32, lpKeyState uintptr, lpCharBuffer *uint32, uFlags uint32) uintptr {
	intResult, _, _ := pToAscii.Call(uintptr(uVirtKey), uintptr(uScanCode), lpKeyState, uintptr(unsafe.Pointer(lpCharBuffer)), uintptr(uFlags))
	return intResult
}

func GetKeyState(nVirtKey int) uintptr {
	short, _, _ := pGetKeyState.Call(uintptr(nVirtKey))
	return short
}

func GetKeyboardState(lpKeyState uintptr) bool {
	success, _, _ := pGetKeyBoardState.Call(lpKeyState)
	if success == 0 {
		return false
	}
	return true
}
