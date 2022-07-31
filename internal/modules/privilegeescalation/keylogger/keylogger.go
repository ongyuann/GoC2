package keylogger

import "errors"

func StopKeyLogger() (string, error) {
	return "Not Available On This Platform", nil
}
func StartKeyLogger() error {
	return errors.New("Not Available On This Platform.")
}
