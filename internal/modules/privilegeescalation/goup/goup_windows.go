//go:build windows
// +build windows

package goup

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"

	"golang.org/x/sys/windows/registry"
)

type VulnService struct {
	ServiceName   string
	StartType     string
	Executable    string
	ModifiableDir string
}

type VulnRunKey struct {
	AutorunLocation string
	BinaryPath      string
	WriteableDir    string
}

type AutoLogon struct {
	DomainName    string
	UserName      string
	Password      string
	AltDomainName string
	AltUserName   string
	AltPassword   string
}

var autologonLocation string = "Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon"

var autorunLocations = [...]string{
	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Run",
	"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnce",
	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunService",
	"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
	"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunService",
	"SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\RunOnceService",
}

func AllChecks() (results string, err error) {
	results += CheckAutoLogons()
	results += CheckAutoRuns()
	results += GetUnquotedServices()
	results += AlwaysInstallElevatedCheck()
	return results, err
}

func CheckIfDirWriteable(path string) bool {
	tempFile, err := os.CreateTemp(path, "__*.log")
	if err != nil {
		return false
	}
	tempFile.Close()
	os.Remove(tempFile.Name())
	return true
}

func CheckAutoLogons() string {
	results := "--- Registry AutoLogons ---\n"
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, autologonLocation, registry.READ)
	if err != nil {
		return results + "Nothing Found.\n"
	}
	defer k.Close()
	val, _, err := k.GetStringValue("AutoAdminLogon")
	if err != nil {
		return results + "Nothing Found.\n"
	}
	if val != "1" {
		return results + "Nothing Found.\n"
	}
	// else get all the passwords here
	defaultDomainName, _, _ := k.GetStringValue("DefaultDomainName")
	defaultUserName, _, _ := k.GetStringValue("DefaultUserName")
	defaultPassword, _, _ := k.GetStringValue("DefaultPassword")
	altDomainName, _, _ := k.GetStringValue("AltDefaultDomainName")
	altUserName, _, _ := k.GetStringValue("AltDefaultUserName")
	altPassword, _, _ := k.GetStringValue("AltDefaultPassword")
	a := &AutoLogon{
		DomainName:    defaultDomainName,
		UserName:      defaultUserName,
		Password:      defaultPassword,
		AltDomainName: altDomainName,
		AltUserName:   altUserName,
		AltPassword:   altPassword,
	}
	data, _ := json.MarshalIndent(a, "", " ")
	results += fmt.Sprintf("%s\n", string(data))
	return results

}

func CheckAutoRuns() string {
	results := "--- Modifiable Registry AutoRun Directories --- \n"
	r, _ := regexp.Compile(`(?i)^\W*([a-z]:\\.+?(\.exe|\.bat|\.ps1|\.vbs))\W*`)
	for _, location := range autorunLocations {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, location, registry.READ)
		if err != nil {
			continue
		}
		defer k.Close()
		values, err := k.ReadValueNames(0)
		if err != nil {
			continue
		}
		for _, v := range values {
			log.Println(v)
			val, _, err := k.GetStringValue(v)
			if err != nil {
				continue
			}
			findings := r.FindStringSubmatch(val)
			if findings == nil {
				continue
			}
			if len(findings) < 1 {
				continue
			}
			executablePath := findings[1]
			pathSplit := strings.Split(executablePath, "\\")
			removeLast := pathSplit[0 : len(pathSplit)-1]
			p := strings.Join(removeLast, "\\")
			if !CheckIfDirWriteable(p) {
				continue
			}
			t := &VulnRunKey{
				AutorunLocation: fmt.Sprintf("HKLM:\\%s", v),
				WriteableDir:    p,
				BinaryPath:      executablePath,
			}
			data, err := json.MarshalIndent(t, "", " ")
			if err != nil {
				continue
			}
			results += fmt.Sprintf("%s\n", string(data))
		}
	}
	if results == "--- Modifiable Registry AutoRun Directories --- \n" {
		results += "Nothing Found.\n"
	}
	return results
}

func AlwaysInstallElevatedCheck() string {
	results := "--- AlwaysInstallElevated --- \n"
	u, err := registry.OpenKey(registry.CURRENT_USER, `SOFTWARE\Policies\Microsoft\Windows\Installer`, registry.ALL_ACCESS)
	if err != nil {
		return results + "Nothing Found.\n"
	}
	defer u.Close()
	val, _, err := u.GetIntegerValue("AlwaysInstallElevated")
	if err != nil {
		return results + "Nothing Found.\n"
	}
	if val != 1 {
		return results + "Nothing Found.\n"
	}
	results += "HKCU Vulnerable\n"
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, `SOFTWARE\Policies\Microsoft\Windows\Installer`, registry.ALL_ACCESS)
	if err != nil {
		results += "HKLM Not Vulnerable\n"
		return results
	}
	defer k.Close()
	val, _, err = k.GetIntegerValue("AlwaysInstallElevated")
	if err != nil {
		return results + "Nothing Found.\n"
	}
	if val != 1 {
		return results + "Nothing Found.\n"
	}
	results += "HKLM Vulnerable\n"
	return results
}

func GetUnquotedServices() string {
	results := "--- Unquoted Services ---\n"
	baseKey, err := registry.OpenKey(registry.LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Services", registry.READ)
	if err != nil {
		return results + "Nothing Found.\n"
	}
	defer baseKey.Close()
	services, err := baseKey.ReadSubKeyNames(0)
	if err != nil {
		return results + "Nothing Found.\n"
	}
	for _, s := range services {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, fmt.Sprintf("SYSTEM\\CurrentControlSet\\Services\\%s", s), registry.READ)
		if err != nil {
			continue
		}
		defer k.Close()
		imagePath, _, err := k.GetStringValue("ImagePath")
		if err != nil {
			continue
		}
		path := strings.Trim(imagePath, "")
		startType := ""
		if path != "" && !strings.HasPrefix(path, "\"") && !strings.HasPrefix(path, "'") && strings.Contains(path[0:strings.Index(strings.ToLower(path), ".exe")+4], " ") {
			startTypeInt, _, err := k.GetIntegerValue("Start")
			if err != nil {
				startTypeInt = 0
			}
			switch startTypeInt {
			case 2:
				startType = "Automatic"
			case 3:
				startType = "Manual"
			case 4:
				startType = "Disabled"
			default:
				startType = "Unknown"
			}
			executablePath := path[0 : strings.Index(strings.ToLower(path), ".exe")+4]
			numSpaces := len(strings.Split(executablePath, " ")) - 1
			for x := 0; x < numSpaces; x++ {
				path := strings.Split(executablePath, " ")[x]
				check := path[0:strings.Index(path, "\\")] + "\\"
				tempFile, err := os.CreateTemp(check, "__*.txt")
				if err != nil {
					continue
				}
				tempFile.Close()
				os.Remove(tempFile.Name())
				v := &VulnService{
					ServiceName:   s,
					StartType:     startType,
					Executable:    executablePath,
					ModifiableDir: check,
				}
				data, _ := json.MarshalIndent(v, "", " ")
				results += fmt.Sprintf("%s\n", string(data))
			}
		}
	}
	if results == "--- Unquoted Services ---\n" {
		return results + "Nothing Found.\n"
	}
	return results
}
