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
	"enum-handles",
	"enum-rwx-memory",
	"remote-inject-stealth",
	"load-custom-coff",
	"load-custom-pe",
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
	"hook-check",     // stable
	"patch-amsi",     // stable
	"patch-etw",      // stable
	"disable-sysmon", // stable
	"unhook-ntdll",   // stable
	"peruns-fart",
	"delete-event-log", //stable
}

var LateralMovementModulesList = [...]string{
	"exit",
	"start-websrv",
	"stop-websrv",
	"start-ws-pivot",
	"stop-ws-pivot",
	"start-http-pivot",
	"stop-http-pivot",
	"winrm-exec", // stable
	"wmi-exec",
	"smb-exec",             // stable
	"ps-exec",              // stable
	"list-remote-services", // stable
	"list-loggedon-users",  // stable
	"fileless-service",     // stable
	"admin-check",          // stable
}

var PrivilegeEscalationModulesList = [...]string{
	"exit",
	"shell-history", // stable
	"start-keylogger",
	"stop-keylogger",
	"start-clipboard-monitor",
	"stop-clipboard-monitor",
}

var PersistenceModulesList = [...]string{
	"exit",
	"powershell-profile", // stable
	"run-key",
	"logon-script",
	"launch-items",
	"login-items",
	"crontab",
	"add-user",          // stable
	"remove-user",       // stable
	"add-user-group",    // stable
	"remove-user-group", // stable
}

var EnumerationModulesList = [...]string{
	"exit",
	"console-check", // stable
	"dotnet-check",  // stable
	"env",           // stable
	"enum-drivers",  // stable
	"enum-local",    // stable
	"port-scan",     // stable
	"subnet-scan",   // stable but it sucks
	"ifconfig",      // stable
	"list-pipes",    // stable
	"list-services", // stable
	"list-ports",    // stable
	"list-shares",   // stable
	//"screenshot",
	"nslookup",       // stable
	"reverse-lookup", // stable
}

var CredentialsModulesList = [...]string{
	"exit",
	"dump-secrets",        // stable
	"dump-secrets-remote", // stable
	"dump-process",        // stable
	"dump-credential-mgr", // stable
}

var ImpersonationModulesList = [...]string{
	"exit",
	"show-priv",    //stable
	"enable-priv",  // stable
	"disable-priv", // stable
	"enum-tokens",  // stable
	"get-system",   // stable
	"steal-token",  // stable
	"logon-user",   // stable
	"logon-user-netonly",
	"rev2self", // stable
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
