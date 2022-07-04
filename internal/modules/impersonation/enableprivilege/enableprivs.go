//go:build darwin || linux
// +build darwin linux

package enableprivilege

import "fmt"

func EnablePriv(priv string) (string, error) {
	return fmt.Sprintf("Not Available On this platform."), nil
}
