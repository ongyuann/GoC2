//go:build darwin || linux
// +build darwin linux

package exectools

func PsExec(args []string) (string, error) {
	return "NotAvailable.", nil
}
