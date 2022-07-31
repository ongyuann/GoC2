//go:build darwin
// +build darwin

package memfdcreate

func MemfdCreate(data []byte, fakeFileName string) (string, error) {
	return "Not Available on this platform.", nil
}
