//go:build darwin || linux
// +build darwin linux

package enumtokens

func EnumTokens() (string, error) {
	return "Not available on this platform.", nil
}
