//go:build darwin || linux
// +build darwin linux

package basic

/*
#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

char* get_user_name(){
	struct passwd *pwd;
	pwd = getpwuid(getuid());
	return pwd->pw_name;
}
*/
import "C"

import (
	"fmt"
)

func WhoAmI() (string, error) {
	//c go test basically.
	nameptr := C.get_user_name()
	name := C.GoString(nameptr)
	return fmt.Sprintf("%s", name), nil
}

func GetIntegrity() string {
	return "Not Available On This Platform."
}
