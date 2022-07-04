//go:build darwin || linux
// +build darwin linux

package admincheck

func AdminCheck(remoteMachine string) (string, error) {
	return "Not Available On This Platform.", nil
}
