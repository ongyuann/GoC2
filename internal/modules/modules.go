package modules

/* TO DO

* Add Linux implementations of stuff (syscalls and /proc)
* Add Macos implementations of stuff

- credentials
* dump process with raw syscalls.


* Finish sharp up clone

- evasion
* add patch credential guard https://itm4n.github.io/credential-guard-bypass/
* unhook dll with raw syscalls.


* BELOW DOESNT WORK ON WINDOWS 11 APPARENTLY.
* add disable defender. -> stop service then update to be disabled.
* add renabler defender -> do reverse of above.
  [5] ACCESS_ALLOWED_ACE_TYPE: NT SERVICE\TrustedInstaller
        SERVICE_ALL_ACCESS
  [6] ACCESS_ALLOWED_ACE_TYPE: NT SERVICE\WinDefend
        SERVICE_ALL_ACCESS

* add disable defender for endpoint. -> disable firewall, then do the above? supposedly doesnt work.
* FIXED in windows 11
* https://twitter.com/jonasLyk/status/1513576862131310600


- driver
* finish driver and get a certificate for it.

	// removed use external dlls and custom pe load or shinject
	//"port-forward",
	//"revert-port-forward",
	//"create-service",
	//"start-service",
	//"stop-service",
	//"delete-service",
	//"create-scheduled-task",
	//"execute-scheduled-task",
	//"delete-scheduled-task",
	//"modify-service-binary",
	//"go-up", // sharpup for golang -> doesnt work :(

*/
var ExecutionModulesList = [...]string{
	"exit",
	"powershell",
	"list-library",
	"load-library",
	"free-library",
	"module-stomp",
	"enum-rwx-memory",
	"remote-inject-stealth",
	"load-custom-pe",
	"load-custom-pe-pipe",
	"memfd_create",
	"self-inject",
	"raw-self-inject",
	"spawn-inject",
	"spawn-inject-token",
	"spawn-inject-creds",
	"spawn-inject-pipe",
	"remote-inject",
	"create-process-token",
	"create-process-creds",
	"run",
	"reverse-shell",
}

var EvasionModulesList = [...]string{
	"exit",
	"hook-check",
	"patch-amsi",
	"patch-etw",
	"disable-sysmon",
	"unhook-ntdll",
	"peruns-fart",
	"delete-event-log",
}

var LateralMovementModulesList = [...]string{
	"exit",
	"winrm-exec",
	"wmi-exec",
	"smb-exec",
	"ps-exec",
	"list-remote-services",
	"list-loggedon-users",
	"fileless-service",
	"admin-check",
}

var PrivilegeEscalationModulesList = [...]string{
	"exit",
	"shell-history",
	"start-keylogger",
	"stop-keylogger",
	"start-clipboard-monitor",
	"stop-clipboard-monitor",
}

var PersistenceModulesList = [...]string{
	"exit",
	"powershell-profile",
	"run-key",
	"logon-script",
	"launch-items",
	"login-items",
	"crontab",
	"add-user",
	"remove-user",
	"add-user-group",
	"remove-user-group",
}

var EnumerationModulesList = [...]string{
	"exit",
	"dotnet-check",
	"env",
	"enum-drivers",
	"port-scan",
	"subnet-scan",
	"ifconfig",
	"list-pipes",
	"list-services",
	"list-ports",
	"list-shares",
	"enum-local",
	//"screenshot",
	"nslookup",
	"reverse-lookup",
}

var CredentialsModulesList = [...]string{
	"exit",
	"dump-secrets",
	"dump-secrets-remote",
	"dump-process",
	"dump-credential-mgr",
}

var ImpersonationModulesList = [...]string{
	"exit",
	"show-priv",
	"enable-priv",
	"disable-priv",
	"enum-tokens",
	"get-system",
	"steal-token",
	"logon-user",
	"logon-user-netonly",
	"rev2self",
}

var BasicModulesList = [...]string{
	"info", "exit", "sleep", "jitter", "pwd", "cd", "rm", "cp", "mv", "ls", "cat", "touch", "ps", "hostname", "whoami", "mkdir", "rmdir", "killproc", "exit-process", "exit-thread", "shell", "download", "remote-download", "upload",
	"enumeration",
	"impersonation",
	"persistence",
	"lateral-movement",
	"execution",
	"evasion",
	"privilege-escalation",
	"credentials",
}
