package clipboardmonitor

import "errors"

func StartClipboardMonitor() (string, error) {
	return "Not Available on this platform", errors.New("Not Available On This Platform.")
}

func StopClipboardMonitor() (string, error) {
	return "Not Available on this platform", errors.New("Not Available On This Platform.")
}
