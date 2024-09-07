---
title: "Troubleshooting IIS Authentication"
date: 2024-09-07
---

While I was preparing a dummy website for my lab, I encounter a `HTTP Error 401.3 - Unauthorized` error. For some reason, I've never setup an IIS website from scratch, the only work I've done related to them is to troubleshoot up-and-running sites.
![image](https://github.com/user-attachments/assets/264e4621-4be1-4dc8-85e6-dd8e0fa6ce40)

I've been using a bunch of tools from the SysInternals for a while now (mainly Process Explorer, Process monitor and Tcpview), few tools are as useful as this when there's the need to troubleshoot somethig in Windows (talking specifically about third-party software). I believe I onced faced this issue when I was an intern, and a senior engineer helped me solving this. The thing is, that the procedure the engineer did was to add "likely" Windows/IIS accounts that could've been the root cause of this issue, I remember it took a bit of time doing this trial-and-error procedure.

Today when I saw this issue, I thought: Some IIS process must not be able to access the folder of my website. Process Monitor would be an excellent option to use here, as it tracks all the system activities that happen. So let's get hands on work...

The procedure I follow is:

1. Open Procmon and let it run for a few seconds
2. Eliminate process names that - in my criteria - are only noise. In my case, this are the processes that I added an exception for
![image](https://github.com/user-attachments/assets/89976c70-5e38-4475-a71a-97552ed5e036)
3. Start the capture again and then reproduce the issue.
4. Look for indicators that could tell the root cause of the issue. If needed repeat step 2.

From the book "Troubleshooting with the Windows Sysinternals Tools.pdf", I know that I should be looking for an `ACCESS DENIED` value in the `Result` column.
![image](https://github.com/user-attachments/assets/9d04f5d0-ae6b-4072-9874-7ad8dff5a7c6)

When applying the filter, we can state with confidence that the root cause of this issue is: 
![image](https://github.com/user-attachments/assets/97c0ae65-3bc6-4a6a-8a55-95863da3b32a)

Reading the third entry, there's what seems to be a built-in account `NT AUTHORITY\IUSR` that the process `w3wp.exe` is attempting to read the contents of the folder `C:\Users\Administrator\Documents\website`
![image](https://github.com/user-attachments/assets/2b4cd3aa-abdb-4725-8637-3ebaf93cd0b9)

Investigating this account this [MS article](https://learn.microsoft.com/en-us/iis/get-started/planning-for-security/understanding-built-in-user-and-group-accounts-in-iis) states the following:
> This built-in account does not need a password and will be the default identity that is used when anonymous authentication is enabled.

In my case, this makes sense as I do have `anonymousAuthentication` set as `true`.
![image](https://github.com/user-attachments/assets/fee6be65-303b-4210-95ff-263a1c9c1e84)

All this information that we have reviewed, indicates that we need to give `NT AUTHORITY\IUSR` reading permission to the folder `C:\Users\Administrator\Documents\website`.
Once that's done, we are now able to access

![image](https://github.com/user-attachments/assets/4c17aa34-5574-4ff9-9d47-d83670194d55)
