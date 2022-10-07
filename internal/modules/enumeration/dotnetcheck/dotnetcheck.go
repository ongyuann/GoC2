package dotnetcheck

import (
	"fmt"
	"strings"

	"golang.org/x/sys/windows/registry"
)

func DotnetCheck() (string, error) {
	var result string = "### DotNet Versions ### \n"
	key, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\NET Framework Setup\NDP`, registry.READ)
	if err != nil {
		return "", err
	}
	defer key.Close()
	subKeys, err := key.ReadSubKeyNames(-1)
	if err != nil {
		return "", err
	}
	for _, s := range subKeys {
		if strings.Contains(s, "v") {
			result += fmt.Sprintf("Version %s\n", s)
		}
	}
	return result, nil
}
