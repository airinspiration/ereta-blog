---
title: "Campfire-1 Sherlock"
date: 2024-06-22
---
![image](https://github.com/airinspiration/ereta-blog/assets/99099600/1bcabc67-d1c9-4503-bd84-d25dac278923)

# What to expect
Examine artifacts and logs from a Domain Controller, as well as endpoint artifacts from where Kerberoast attack activity originated. We will explore what to look for to properly identify Kerberoasting attack activity and how to avoid false positives given the complexity of Active Directory.

# Evidence provided
1. Security Logs from Domain Controller
2. PowerShell-Operational Logs from the affected workstation
3. Prefetech Files from the affected workstation

# Technical Analysis
### Task 1
Analyzing Domain Controller Security Logs, can you confirm the date & time when the kerberoasting activity occurred? \
R = **2024-05-21 03:18:09**

After refreshing the topic of keberoasting using the following resources: [one](https://www.intrinsec.com/kerberos_opsec_part_1_kerberoasting/?cn-reloaded=1), [two](https://www.intrinsec.com/kerberos_opsec_part_1_kerberoasting/?cn-reloaded=1); I went on the hunt. \
\
This techniques involves the request of Ticket Granting Service tickets, as it that ticket iself is encrypted using the user's secret, which once cracked can expose the secret of the requested service. Performing Kerberoasting involves in looking for SPNs that support the RC4 encryption algorithm, as it is susceptible to password cracking tools. After knowing this, it's implicit that we start filter in the evtx file by ID 4769 - I am using "Event Log Explorer".
![image](https://github.com/airinspiration/ereta-blog/assets/99099600/3c0c64d6-6d23-4d46-89dd-c23f231c192c)

As I mentioned, when performing Kerberoasting, SPN's that support RC4 are looked for. How does this reflects in the WinEvent Log?

Looking at the event [documentation](https://learn.microsoft.com/en-us/previous-versions/windows/it-pro/windows-10/security/threat-protection/auditing/event-4769), we have to look for  the value of the field `Ticket Encryption Type` being `0x17`, from the short research I've done 0x18 is never mentioned, but it would be worth still looking for it as well.

![image](https://github.com/airinspiration/ereta-blog/assets/99099600/730221f1-e9bc-4162-bcaf-f575d08aaab3)

Once I went through the logs, there is only one log matching the encryption type, we can notice that the Service Name to which it requested access to is MSSQLService, thus, it's intent is to move laterally (e.g into other systems) or even horizontally (e.g account has higher privileges within the domain) using the MSSQLService account.

> Consider that the time chooses to show you the logs is your local time, make sure to add or substract the pertinent hours.

![image](https://github.com/airinspiration/ereta-blog/assets/99099600/b66da949-a896-48f2-b72c-fbaf7031c7e3)

### Task 2
What is the Service Name that was targeted? \
**R= MSSQLService**

From the last log shown in Task 1, kerberos ticket was requested in order to access MSSQLService.

### Task 3
It is really important to identify the Workstation from which this activity occurred. What is the IP Address of the workstation? \
**R= 172.17.79.129**

![image](https://github.com/airinspiration/ereta-blog/assets/99099600/2f4ff678-2ec2-4692-9933-f490bec4d078)

### Task 4
Now that we have identified the workstation, a triage including PowerShell logs and Prefetch files are provided to you for some deeper insights so we can understand how this activity occurred on the endpoint. What is the name of the file used to Enumerate Active directory objects and possibly find Kerberoastable accounts in the network? \
**R= powerview.ps1**

Almost all of the powershell logs indicate usage of powerview, which can be used to perform AD enum and possible kerberoastable accounts.
![image](https://github.com/airinspiration/ereta-blog/assets/99099600/bf386680-4c61-4977-9683-ce28ef55d92d)


### Task 5
When was this script executed? \
**R=2024-05-21 03:16:32**

Going through the logs, we notice that the first attempt of execution was failed, due to the Execution Policy set at that moment.
![image](https://github.com/airinspiration/ereta-blog/assets/99099600/2d5ee12c-c2c5-420e-895b-07e231e13d50)

Afterwards, the ExecutionPolicy was set to `bypass`, in order to allow execution of third party scripts
![image](https://github.com/airinspiration/ereta-blog/assets/99099600/b8e040cd-7e36-4b86-bd8e-e28166224428)

Then, we can appreciate the 4104 event "Execute a Remote Command". Which gives enough evidence to confirm that powerview.ps1 was executed correctly.

![image](https://github.com/airinspiration/ereta-blog/assets/99099600/73c4419c-23bc-47b1-9669-b3f74a0ede6f)

### Task 6
What is the full path of the tool used to perform the actual kerberoasting attack? \
**R=C:\Users\Alonzo.spire\Downloads\Rubeus.exe**

Using Eric Zimmerman `PECmd` in order to analyze the prefetch files, we were able to find the file executed at the time of the kerberoasting activity detected in the Domain Controller WinEventLog file, which is another known tool widely used to perform kerberoasting.
![image](https://github.com/airinspiration/ereta-blog/assets/99099600/66054dd7-924b-45d2-a746-5c944d927071)

### Task 7
When was the tool executed to dump credentials? \
**R=2024-05-21 03:18:08** 

Looking at the `RunTime` column of the detected `RUBEUS.EXE` file, it was run on `2024-05-21 03:18:08`
![image](https://github.com/airinspiration/ereta-blog/assets/99099600/6a7510bb-babf-4dd9-ae94-371868efb272)
