//go:build darwin || linux
// +build darwin linux

package dumpsecrets

func DumpHashes() (string, error) {
	return "Read /etc/shadow", nil
}

func DumpSecrets() (string, error) {
	return "Not available on this platform", nil
}

func DumpSecretsRemote(args []string) (string, error) {
	return "Read /etc/shadow", nil
}
