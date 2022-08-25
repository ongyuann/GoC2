package basic

import (
	"fmt"
	"io"
	"os"
)

func CopyFile(args []string) (string, error) {
	if len(args) < 2 {
		return "", fmt.Errorf("Not Enough Args.")
	}
	source := args[0]
	destination := args[1]
	sourceStat, err := os.Stat(source)
	if err != nil {
		return "", err
	}
	if sourceStat.Mode().IsDir() {
		return "", fmt.Errorf("%s is a directory.", source)
	}
	if !sourceStat.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", source)
	}
	srcFile, err := os.Open(source)
	if err != nil {
		return "", err
	}
	defer srcFile.Close()
	dest, err := os.Create(destination)
	if err != nil {
		return "", err
	}
	defer dest.Close()
	nBytes, err := io.Copy(dest, srcFile)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("Copied %s to %s Wrote %d bytes", source, destination, nBytes), nil
}
