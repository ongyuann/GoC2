//go:build darwin || linux
// +build darwin linux

package runkey

func RegistryRunKeyPersist(args []string) (string, error) {
	return "Not Available On This Platform", nil
}
