---
title: "Traffic Analysis Exercise: Download from fake software site"
date: 2025-03-09
---

# Questions

### **1. In the memory dump analysis, determining the root of the malicious activity is essential for comprehending the extent of the intrusion. What is the name of the parent process that triggered this malicious behavior?**
R= lssass.exe

Taking a look, using the command `python3 vol.py -f "../../Artifacts/Windows 7 x64-Snapshot4.vmem" windows.pstree`, we observe that there are two processes that look off to me, PID `1604` and `2748`. `1604` is a VMWare 
Tools core component which handlex background tasks, to my knowledge, it should be straight up executing a `cmd.exe` which calls for `ipconfig.exe`. The other process that looks very off is `lssass.exe` (PID `2748`), as you can
tell by simply looking at the name, it is trying to make the user believe that it is the core process `lsass.exe` (which we can see it seven processes above [PID `508`]).

![image](https://github.com/user-attachments/assets/7910fd62-7de4-48ee-9833-90c83bdf552a)

Now, using the plugin `windows.cmdline` to look at the commandline that was executed for each of the processes, we can see that `lssass.exe` is located in the publicly writable `%TEMP%` folder, which is a well-known location that
threat actors leverage to put their malicious payloads in. Also, if we look one line under, its child `rundll.exe` (PID `3064`) is executing a dll called `clip64.dll`. Googling up this dll, it is referenced in the [Data Collection
And Exfiltration (.DLL Plugins)](https://www.splunk.com/en_us/blog/security/amadey-threat-analysis-and-detections.html#:~:text=Data%20Collection%20And%20Exfiltration%20(.DLL%20Plugins)) section in a blog of the Splunk Threat Research
Team. According to them, `clip64.dll` is one of two dlls that "_...play a crucial role in collecting sensitive information..._"

![image](https://github.com/user-attachments/assets/0dda2dd4-12bc-40b9-9c3d-3a72bb7f8379)


With the previous evidence, we have more than enough to state that `lssass.exe` is the disguised Amadey Trojan Stealer.

### **2. Once the rogue process is identified, its exact location on the device can reveal more about its nature and source. Where is this process housed on the workstation?**
R= C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\lssass.exe

As we saw in the evidence provided in last's question answer, the file is located in `C:\Users\0XSH3R~1\AppData\Local\Temp\925e7e99c5\`

### **3. Persistent external communications suggest the malware's attempts to reach out C2C server. Can you identify the Command and Control (C2C) server IP that the process interacts with?**
R= 41.75.84.1

Leveraging the plugin `windows.netscan`, it's notorious that the information in the first entry is malformed, lacking values in `source ip`/`source port` and the destination port is 0. On the other side, there were two connection
attempts to `41.75.84.12` - both which have logical information.

![image](https://github.com/user-attachments/assets/2ddf51fa-572a-490f-9983-fcf5ee55e7f9)

### **4. Following the malware link with the C2C, the malware is likely fetching additional tools or modules. How many distinct files is it trying to bring onto the compromised workstation?**
R= 2

By looking for GET requests, we can see that it has two GET requests for `/rock/Plugins/cred64.dll` and `/rock/Plugins/clip64.dll`.

![image](https://github.com/user-attachments/assets/74afc39d-7463-4036-bd03-78b565f43615)

### **5. Identifying the storage points of these additional components is critical for containment and cleanup. What is the full path of the file downloaded and used by the malware in its malicious activity?**
R= C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll

Leveraging the `windows.cmdline` plugin, the file path is `C:\Users\0xSh3rl0ck\AppData\Roaming\116711e5a2ab05\clip64.dll`

![image](https://github.com/user-attachments/assets/c7101f30-150a-43a7-b509-34632d01e736)

### **6. Once retrieved, the malware aims to activate its additional components. Which child process is initiated by the malware to execute these files?**
R= rundll32.exe

From the screenshot in Q5, we can observe rundll32.exe was the process that executed `clip64.dll`

### **7. Understanding the full range of Amadey's persistence mechanisms can help in an effective mitigation. Apart from the locations already spotlighted, where else might the malware be ensuring its consistent presence?**
R= C:\Windows\System32\Tasks\lssass.exe

Scanning the filesystem for files that have been recently accessed, we can see that there's another location where `lssass.exe` was written in.
![image](https://github.com/user-attachments/assets/385cd18a-3960-4a66-8bb1-02bf8c09dd55)




