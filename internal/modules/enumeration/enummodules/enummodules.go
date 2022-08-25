package enummodules

import (
	"strconv"

	"github.com/latortuga71/GoC2/pkg/winapi"
)

func EnumProcessModules(pid string) (string, error) {
	iPid, err := strconv.Atoi(pid)
	if err != nil {
		return "", err
	}
	return winapi.EnumModules(uint32(iPid))
}
