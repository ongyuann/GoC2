//go:build darwin || linux
// +build darwin linux

package loginitems

// #cgo LDFLAGS: -framework CoreServices
/*
#include <CoreServices/CoreServices.h>
#include <stdio.h>

int AddLoginItem(char* buffer){
    size_t buffer_len = strlen(buffer);
    CFURLRef pathAsUrl = CFURLCreateFromFileSystemRepresentation(NULL,buffer,buffer_len,true);
    if (pathAsUrl == NULL){
        printf("Failed to create path\n");
        return 1;
    }
    LSSharedFileListRef list = LSSharedFileListCreate(0x0,kLSSharedFileListSessionLoginItems,0x0);
    if (list == NULL){
        printf("Failed to get list of login items\n");
        return 1;
    }
    LSSharedFileListInsertItemURL(list,kLSSharedFileListItemLast,NULL,NULL,pathAsUrl,NULL,NULL);
    CFRelease(pathAsUrl);
    return 0;
}
*/
import "C"
import (
	"errors"
	"os"
	"unsafe"
)

func InsertLoginItem(path string) (string, error) {
	_, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	var cstr = C.CString(path)
	defer C.free(unsafe.Pointer(cstr))
	result := C.AddLoginItem(cstr)
	if result == 1 {
		return "", errors.New("Failed to install login-item.")
	}
	return "[+] Successfully Installed Login Item", nil
}
