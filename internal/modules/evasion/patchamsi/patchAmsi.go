//go:build darwin || linux
// +build darwin linux

package patchamsi

func PatchAmsi() (string, error) {
	return "Not Available On This OS", nil
}
