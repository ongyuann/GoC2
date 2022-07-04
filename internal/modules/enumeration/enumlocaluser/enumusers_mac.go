//go:build darwin
// +build darwin

package enumlocaluser

import "os/exec"

func EnumDomain() (string, error) {
	return "Not Available On This Platform", nil
}

func EnumGroups() (string, error) {
	results := "--- Groups --- \n"
	cmd := exec.Command("bash", "-c", "dscl . list /Groups | grep -v '^_'")
	data, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	results += string(data)
	return results, nil
}

func EnumUsers() (string, error) {
	results := "--- Users --- \n"
	cmd := exec.Command("bash", "-c", "dscl . list /Users | grep -v '^_'")
	data, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	results += string(data)
	return results, nil
}
