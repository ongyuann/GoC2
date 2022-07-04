//go:build darwin || linux
// +build darwin linux

package patchetw

func PatchEtw() (string, error) {
	return "Not Available On This OS", nil
}
