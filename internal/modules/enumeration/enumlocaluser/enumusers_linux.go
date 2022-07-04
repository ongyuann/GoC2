//go:build linux
// +build linux

package enumlocaluser

import "os/exec"

func EnumDomain() (string, error) {
	return "Not Available On This Platform", nil
}

func EnumGroups() (string, error) {
	results := "--- Groups --- \n"
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return "", err
	}
	results += string(data)
	return results, nil
}

func EnumUsers() (string, error) {
	results := "--- Users --- \n"
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return "", err
	}
	results += string(data)
	return results, nil
}
