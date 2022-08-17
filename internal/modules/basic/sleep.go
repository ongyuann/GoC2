package basic

import (
	"fmt"
	"strconv"
	"time"
)

func Sleep(sleepSeconds string) (string, error) {
	sec, err := strconv.Atoi(sleepSeconds)
	if err != nil {
		return "", err
	}
	time.Sleep(time.Second * time.Duration(sec))
	return fmt.Sprintf("Slept for %s", sleepSeconds), nil
}
