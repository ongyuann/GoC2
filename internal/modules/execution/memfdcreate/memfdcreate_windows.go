//go:build windows
// +build windows

package memfdcreate

func MemfdCreate(data []byte, fakeFileName string) (string, error) {
	return "Not Available on this platform.", nil
}
