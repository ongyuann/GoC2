//go:build linux
// +build linux

package basic

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/user"
	"strconv"
	"strings"
)

type Process struct {
	Pid   string `json:"pid"`
	Name  string `json:"name"`
	Owner string `json:"owner"`
}

func ExtractInfo(lines []string) Process {
	id := strings.Split(lines[8], "\t")[1]
	userInfo, err := user.LookupId(id)
	if err != nil {
		log.Fatal(err)
	}
	p := Process{
		Pid:   strings.Split(lines[5], "\t")[1],
		Name:  strings.Split(lines[0], "\t")[1],
		Owner: userInfo.Name,
	}
	return p
}

func ListProcesses() (string, error) {
	results := ""
	procDirs, err := os.ReadDir("/proc")
	if err != nil {
		log.Fatal(err)
	}
	for _, dir := range procDirs {
		if dir.IsDir() {
			info, err := dir.Info()
			if err != nil {
				log.Fatal(err)
			}
			name := info.Name()
			if _, err := strconv.Atoi(name); err != nil {
				continue
			}
			status := fmt.Sprintf("/proc/%s/status", name)
			cmdline := fmt.Sprintf("/proc/%s/cmdline", name)
			cmdlineData, err := os.ReadFile(cmdline)
			if err != nil {
				cmdlineData = nil
			}
			cmdlineString := strings.Split(string(cmdlineData), "\000")
			fd, err := os.Open(status)
			if err != nil {
				continue
			}
			defer fd.Close()
			scanner := bufio.NewScanner(fd)
			fileLines := make([]string, 0)
			for scanner.Scan() {
				fileLines = append(fileLines, scanner.Text())
			}
			procInfoStruct := ExtractInfo(fileLines)
			results += fmt.Sprintf("%-20s %-20s %-10s %s \n", procInfoStruct.Owner, procInfoStruct.Pid, procInfoStruct.Name, strings.Join(cmdlineString, " "))
			if err := scanner.Err(); err != nil {
				log.Fatal(err)
			}
		}
	}
	return results, nil
}
