//go:build darwin || linux
// +build darwin linux

package processinjection

func SelfInject(shellcode []byte) (string, error) {
	return "Not Available On This Platform.", nil
}

func RemoteInject(shellcode []byte, pid string) (string, error) {
	return "Not Available On This Platform.", nil
}
func SpawnInject(shellcode []byte, pid string) (string, error) {
	return "Not Available On This Platform.", nil
}

func SpawnInjectReadPipe(shellcode []byte, pid string) (string, error) {
	return "Not Available On This Platform.", nil
}

func RawSelfInject(shellcode []byte) (string, error) {
	return "Not Available On This Platform.", nil
}
