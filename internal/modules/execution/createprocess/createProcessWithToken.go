//go:build darwin || linux
// +build darwin linux

package createprocess

func CreateProcessWithTokenViaPid(args []string) (string, error) {
	return "Not available on this platform", nil

}

func CreateProcessWithTokenViaCreds(args []string) (string, error) {
	return "Not available on this platform", nil
}
