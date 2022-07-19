//go:build windows
// +build windows

package launchitems

func PersistLaunchItems(args []string) (string, error) {
	return "Not available on this platform.", nil
}
