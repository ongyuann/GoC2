package winapi

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	pModUser32           = syscall.NewLazyDLL("user32.dll")
	pGetDesktopWindow    = pModUser32.NewProc("GetDesktopWindow")
	pGetWindowRect       = pModUser32.NewProc("GetWindowRect")
	pEnumDisplayMonitors = pModUser32.NewProc("EnumDisplayMonitors")
	pGetMonitorInfo      = pModUser32.NewProc("GetMonitorInfoW")
	pEnumDisplaySettings = pModUser32.NewProc("EnumDisplaySettingsW")
	pEnumChildWindows    = pModUser32.NewProc("EnumChildWindows")
	pShowWindow          = pModUser32.NewProc("ShowWindow")

	pSetWindowsHookExW             = pModUser32.NewProc("SetWindowsHookExW")
	pGetForegroundWindow           = pModUser32.NewProc("GetForegroundWindow")
	pGetWindowTextW                = pModUser32.NewProc("GetWindowTextW")
	pCallNextHookEx                = pModUser32.NewProc("CallNextHookEx")
	pUnhookWindowsHookEx           = pModUser32.NewProc("UnhookWindowsHookEx")
	pGetMessageW                   = pModUser32.NewProc("GetMessageW")
	pDispatchMessageW              = pModUser32.NewProc("DispatchMessageW")
	pLoadCursorW                   = pModUser32.NewProc("LoadCursorW")
	pPostQuitMessage               = pModUser32.NewProc("PostQuitMessage")
	pRegisterClassExW              = pModUser32.NewProc("RegisterClassExW")
	pTranslateMessage              = pModUser32.NewProc("TranslateMessage")
	pPostThreadMessageW            = pModUser32.NewProc("PostThreadMessageW")
	pGetKeyBoardState              = pModUser32.NewProc("GetKeyboardState")
	pGetKeyState                   = pModUser32.NewProc("GetKeyState")
	pToAscii                       = pModUser32.NewProc("ToAscii")
	pGetAsyncKeyState              = pModUser32.NewProc("GetAsyncKeyState")
	pCloseClipboard                = pModUser32.NewProc("CloseClipboard")
	pPeekMessage                   = pModUser32.NewProc("PeekMessageW")
	pSendMessage                   = pModUser32.NewProc("SendMessageW")
	pAddClipBoardFormatListener    = pModUser32.NewProc("AddClipboardFormatListener")
	pRemoveClipBoardFormatListener = pModUser32.NewProc("RemoveClipboardFormatListener")
	pGetWindowTextLengthW          = pModUser32.NewProc("GetWindowTextLengthW")
	PIsClipboardFormatAvailable    = pModUser32.NewProc("IsClipboardFormatAvailable")
	pOpenClipboard                 = pModUser32.NewProc("OpenClipboard")
	PGetClipboardData              = pModUser32.NewProc("GetClipboardData")
	pCreateWindowExW               = pModUser32.NewProc("CreateWindowExW")
	pDefWindowProcW                = pModUser32.NewProc("DefWindowProcW")
	pDestroyWindow                 = pModUser32.NewProc("DestroyWindow")
)

type WNDCLASSEXW struct {
	Size       uint32
	Style      uint32
	WndProc    uintptr
	ClsExtra   int32
	WndExtra   int32
	Instance   syscall.Handle
	Icon       syscall.Handle
	Cursor     syscall.Handle
	Background syscall.Handle
	MenuName   *uint16
	ClassName  *uint16
	IconSm     syscall.Handle
}

const (
	HC_ACTION        = 0
	WM_APP           = 0x8000
	WM_KEYDOWN       = 0x0100
	WH_KEYBOARD_LL   = 13
	VK_LSHIFT        = 0xA0
	VK_RSHIFT        = 0xA1
	VK_CAPITAL       = 0x14
	ShiftKey         = 16
	Capital          = 20
	cWS_MAXIMIZE_BOX = 0x00010000
	cWS_MINIMIZEBOX  = 0x00020000
	cWS_THICKFRAME   = 0x00040000
	cWS_SYSMENU      = 0x00080000
	cWS_CAPTION      = 0x00C00000
	cWS_VISIBLE      = 0x10000000

	cWS_OVERLAPPEDWINDOW       = 0x00CF0000
	cSW_SHOW             int32 = 5
	cSW_USE_DEFAULT      int64 = 0x80000000
	cWM_DESTROY                = 0x0002
	cWM_CLOSE                  = 0x0010
	cIDC_ARROW                 = 32512
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

func ShowWindowW(hWindow uintptr, nCmdShow uint32) {
	pShowWindow.Call(hWindow, uintptr(nCmdShow))
}

func SendMessage(handle, val1, val2, val3 uintptr) {
	pSendMessage.Call(handle, val1, val2, val3)
}

func CloseClipboard() {
	pCloseClipboard.Call()
}

func OpenClipboard(handle uintptr) {
	pOpenClipboard.Call(handle)
}

func GetWindowTextLengthW(handle uintptr) uintptr {
	res, _, _ := pGetWindowTextLengthW.Call(handle)
	return res
}

func AddClipboardFormatListener(handle uintptr) uintptr {
	res, _, _ := pAddClipBoardFormatListener.Call(handle)
	return res
}

func RemoveClipboardFormatListener(handle uintptr) uintptr {
	res, _, _ := pRemoveClipBoardFormatListener.Call(handle)
	return res
}

func PeekMessage(msg *MSG, hwnd syscall.Handle, msgFilterMin, msgFilterMax, wRemoveMsg uint32) (bool, error) {
	ret, _, err := pPeekMessage.Call(
		uintptr(unsafe.Pointer(msg)),
		uintptr(hwnd),
		uintptr(msgFilterMin),
		uintptr(msgFilterMax),
		uintptr(wRemoveMsg),
	)
	if int32(ret) == -1 {
		return false, err
	}
	return int32(ret) != 0, nil
}

func CreateWindow(className, windowName string, style uint64, x, y, width, height int64, parent, menu, instance syscall.Handle) (syscall.Handle, error) {
	ret, _, err := pCreateWindowExW.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(className))),
		uintptr(unsafe.Pointer(syscall.StringToUTF16Ptr(windowName))),
		uintptr(style),
		uintptr(x),
		uintptr(y),
		uintptr(width),
		uintptr(height),
		uintptr(parent),
		uintptr(menu),
		uintptr(instance),
		uintptr(0),
	)
	if ret == 0 {
		return 0, err
	}
	return syscall.Handle(ret), nil
}

func DefWindowProc(hwnd syscall.Handle, msg uint32, wparam, lparam uintptr) uintptr {
	ret, _, _ := pDefWindowProcW.Call(
		uintptr(hwnd),
		uintptr(msg),
		uintptr(wparam),
		uintptr(lparam),
	)
	return uintptr(ret)
}

func DestroyWindow(hwnd syscall.Handle) error {
	ret, _, err := pDestroyWindow.Call(uintptr(hwnd))
	if ret == 0 {
		return err
	}
	return nil
}

func RegisterClassEx(wcx *WNDCLASSEXW) (uint16, error) {
	ret, _, err := pRegisterClassExW.Call(
		uintptr(unsafe.Pointer(wcx)),
	)
	if ret == 0 {
		return 0, err
	}
	return uint16(ret), nil
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

func GetModuleHandle(module string) (syscall.Handle, error) {
	if module == "" {
		ret, _, err := pGetModuleHandleW.Call(0)
		if ret == 0 {
			return 0, err
		}
		return syscall.Handle(ret), nil
	}
	ptr, err := windows.UTF16PtrFromString(module)
	if err != nil {
		return 0, err
	}
	ret, _, err := pGetModuleHandleW.Call(uintptr(unsafe.Pointer(ptr)))
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
