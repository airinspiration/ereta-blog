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

- Are there any results from submitting the SHA256 hash to VirusTotal? \
    **R=** Yes, it is widely detected by anti-virus engines. It's interesting that it is detected as "meterpreter" from the "Threat Label". We now know in advanced that most likely this is the payload from metasploit.
    ![image](https://github.com/user-attachments/assets/e258c7da-7749-46e3-89c9-9561178e7fe9)

- Describe the results of pulling the strings from this binary. Record and describe any strings that are potentially interesting. Can any interesting information be extracted from the strings? \
    **R=** No interesting strings
- Describe the results of inspecting the IAT for this binary. Are there any imports worth noting? \
    **R=** Checks for the presence of debuggers with function _IsDebuggerPresent_ \
    ![image](https://github.com/user-attachments/assets/8bce722b-30c7-4034-849b-64108afcf7a0)

- Is it likely that this binary is packed? \
    **R=** No, way too many visible ASCII strings for the binary to be packed
### Basic Dynamic Analysis
 - Describe initial detonation. Are there any notable occurrences at first detonation? Without internet simulation? With internet simulation?
 - From the host-based indicators perspective, what is the main payload that is initiated at detonation? What tool can you use to identify this?
 - What is the DNS record that is queried at detonation?
 - What is the callback port number at detonation?
 - What is the callback protocol at detonation?
 - How can you use host-based telemetry to identify the DNS record, port, and protocol?
 - Attempt to get the binary to initiate a shell on the localhost. Does a shell spawn? What is needed for a shell to spawn?
