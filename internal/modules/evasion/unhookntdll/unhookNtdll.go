//go:build darwin || linux
// +build darwin linux

package unhookntdll

func UnhookNtdll() (string, error) {
	return "Not available on this platform", nil
}
