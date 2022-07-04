//go:build darwin || linux
// +build darwin linux

package rev2self

func Rev2Self() (string, error) {
	return "Not supported on this platform", nil
}
