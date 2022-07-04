//go:build darwin || linux
// +build darwin linux

package logonscript

func LogonScriptPersist(args []string) (string, error) {
	return "Need to do some cronjob or something.", nil
}
