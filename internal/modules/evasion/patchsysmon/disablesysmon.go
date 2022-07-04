//go:build darwin || linux
// +build darwin linux

package patchsysmon

func DisableSysmon() (string, error) {
	return "Not Available On This Platform YET!.", nil
}
