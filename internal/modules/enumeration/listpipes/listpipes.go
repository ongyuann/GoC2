package listpipes

import (
	"fmt"

	"golang.org/x/sys/windows"
)

func ListPipes() (string, error) {
	var results string
	pipePtr, err := windows.UTF16PtrFromString(`\\.\pipe\*`)
	if err != nil {
		return "", err
	}
	fd := windows.Win32finddata{}
	hFind, err := windows.FindFirstFile(pipePtr, &fd)
	if err != nil {
		return "", err
	}
	fmt.Println("got first")
	for {
		fileName := windows.UTF16PtrToString(&fd.FileName[0])
		results += fmt.Sprintf("%s\n", fileName)
		err = windows.FindNextFile(hFind, &fd)
		if err != nil {
			break
		}
	}
	return results, nil
}
