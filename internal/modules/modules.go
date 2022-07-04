package modules

/* TO DO

* Add Linux implementations of stuff (syscalls and /proc)
* Add Macos implementations of stuff

- credentials
* add credential manager dump from lib
* dump process with raw syscalls.
* add remote option to hashdump

- lateral movement
* add psexec lol
* fix smb exec to use impersonation.
* wmi exec doesnt need impersonation since we dont call service manager.
* test fileless service
* add port scan single port single host

- privesc
* add keylogger
* add clipboard monitor -> already done just need to implement into client.

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

*/
var ExecutionModulesList = [...]string{
	"exit",
	"self-inject",
	"raw-self-inject",
	"spawn-inject",
	"spawn-inject-pipe",
	"remote-inject",
	"create-process-pid",
	"create-process-creds",
	"run",
	"reverse-shell",
}

var EvasionModulesList = [...]string{
	"exit",
	"patch-amsi",
	"patch-etw",
	"disable-sysmon",
	"unhook-ntdll",
	"delete-event-log",
}

var LateralMovementModulesList = [...]string{
	"exit",
	"port-forward",
	"revert-port-forward",
	"create-service",
	"start-service",
	"stop-service",
	"delete-service",
	"create-scheduled-task",
	"execute-scheduled-task",
	"delete-scheduled-task",
	"wmi-exec",
	"smb-exec",
	"admin-check",
}

var PrivilegeEscalationModulesList = [...]string{
	"exit",
	"go-up", // sharpup  for golang
	"shell-history",
	//"keylogger",         // TODO
	//"clipboard-monitor", // Its done just gotta integrate it. (using channels in cmd/client.go etc.)

	// SHARP UP CHECKS
	//"modifiable-scheduled-task-file 	  // todo
	// modifiable services reg key		  // todo
	// modifiable services binary		  // todo
	//"modifiable-services",              // todo
	//"$path-hijack", // https://www.ired.team/offensive-security/privilege-escalation/environment-variable-path-interception https://github.com/GhostPack/SharpUp/blob/master/SharpUp/Checks/HijackablePaths.cs
	// dll hijack
	// unattended install files
	// SHARP UP CHECKS DONE
}

var PersistenceModulesList = [...]string{
	"exit",
	"powershell-profile",
	"run-key",
	"logon-script",
	// bashrc
	// crontab
	// launchd
	// systemd
	// "startup-folder", //todo
	//"wmi-event-sub", // todo sektor 7
	// com-persistence-check
}

var EnumerationModulesList = [...]string{
	"exit",
	"env",
	"subnet-scan",
	"ifconfig",
	"list-services",
	"list-ports",
	"list-shares",
	"enum-users",
	"enum-groups",
	"enum-domain",
	"screenshot",
}

var CredentialsModulesList = [...]string{
	"exit",
	"dump-lsa",
	"dump-process",
	"dump-hashes",
}

var ImpersonationModulesList = [...]string{
	"exit",
	"enum-tokens",
	"get-system",
	"enable-priv",
	"steal-token",
	"rev2self",
}

var BasicModulesList = [...]string{
	"exit", "pwd", "cd", "ls", "cat", "touch", "ps", "whoami", "mkdir", "rmdir", "killproc", "die", "shell", "download", "remote-download", "upload",
	"enumeration",
	"impersonation",
	"persistence",
	"lateral-movement",
	"execution",
	"evasion",
	"privilege-escalation",
	"credentials",
}
