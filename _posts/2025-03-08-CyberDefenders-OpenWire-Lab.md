---
title: "CyberDefenders OpenWire Lab"
date: 2025-03-08
---

# Scenario
During your shift as a tier-2 SOC analyst, you receive an escalation from a tier-1 analyst regarding a public-facing server. This server has been flagged for making outbound connections to multiple suspicious IPs.
In response, you initiate the standard incident response protocol, which includes isolating the server from the network to prevent potential lateral movement or data exfiltration and obtaining a packet capture from
the NSM utility for analysis. Your task is to analyze the pcap and assess for signs of malicious activity.

# Questions
**1. By identifying the C2 IP, we can block traffic to and from this IP, helping to contain the breach and prevent further data exfiltration or command execution. Can you provide the IP of the C2 server that communicated with our server?** \
R= 146.190.21.92 \
Looking at the `Conversations` statistics, the third row seems to stand out, as it's the one that has the larger amount of packets and duration as well.
![image](https://github.com/user-attachments/assets/90e3302a-e00d-457c-b348-d7628906a6fd)

The first HTTP request, is a `GET` type, where `134.209.197.3` is retrieving `invoice.xml` from `146.190.21.92` using port `8000`.
![image](https://github.com/user-attachments/assets/96fb79b0-adcd-494d-a8e2-b42b74e76ba8)

Looking into the details of the response from the destination, the xml file contains instructions to retrieve the file `docker` from `128.199.52.72`, save it as `/tmp/docker`,
give execute rights (using `chmod +x`) and then executing the file.
![image](https://github.com/user-attachments/assets/26ce0a1c-ec16-454f-b898-46398fc4c290)

Here we can see the three way handshake to the IP aforementioned, and the successful retrieval of the file. 
![image](https://github.com/user-attachments/assets/7fb367d5-bf36-481d-a229-b184432b95af)

In this case, the C2 IP is `146.190.21.92` as it`s the one orchestrating the actions required to further compromise the server.

**2. Initial entry points are critical to trace back the attack vector. What is the port number of the service the adversary exploited?** \
R= 61616\
In this case, the threat actor exploited the `ActiveMQ` service, which uses port `61616`.
![image](https://github.com/user-attachments/assets/554b4a80-f131-48fb-9b59-93bd0634ac10)

That makes sense, as the user agent of the first file retrieved `invoice.xml` is from Java.
![image](https://github.com/user-attachments/assets/842f5511-56f4-4e84-a4e5-e203686cf103)

**3. Following up on the previous question, what is the name of the service found to be vulnerable?** \
R= apache activemq

**4. The attacker's infrastructure often involves multiple components. What is the IP of the second C2 server?** \
R= 128.199.52.72 \
As mentioned in Q1, the second stage payload `docker` was downloaded from `128.199.52.72`

**5. Attackers usually leave traces on the disk. What is the name of the reverse shell executable dropped on the server?** \
R= docker \
So far, the only file that we have that we don't know what it does is the one named `docker`. If we extract it using the `Export` > `HTTP object list`, and then
submit it to virustotal, we can see that it detects it as shellcode (code that allows an attacker to get access to the system by spawning a command shell).

![image](https://github.com/user-attachments/assets/4c3562ac-4648-42d6-a5af-8b02cb693723)

**6. What Java class was invoked by the XML file to run the exploit?** \
R= java.lang.ProcessBuilder \
Looking into the xml, we can confirmed that the class `java.lang.ProcessBuilder` was invoked
![image](https://github.com/user-attachments/assets/58f22829-0448-4b8d-bed4-d1d9260ce0ac)

**7. To better understand the specific security flaw exploited, can you identify the CVE identifier associated with this vulnerability?** \
R= CVE-2023-46604 \
Searching in google `activemq port 61616 exploit`, the activity described matches with what we saw.

https://www.huntress.com/blog/critical-vulnerability-exploitation-of-apache-activemq-cve-2023-46604
![image](https://github.com/user-attachments/assets/530a2fe7-9632-4b3a-9389-5574c7618f3f)

![image](https://github.com/user-attachments/assets/6dad42d7-35a3-45f2-8b78-75a4b1a2c683)

**8. As part of addressing the vulnerability, the vendor implemented a validation step to prevent exploitation. Specify the Java class and method where this validation step was added.** \
R= BaseDataStreamMarshaller.createThrowable\
In https://activemq.apache.org/security-advisories.data/CVE-2023-46604-announcement.txt, it mentions that the issue is tracked as `AMQ-9370`.

Looking into that issue, we end in the source code of changes. The change was actually done in multiple versions of the software (as expected). All of them under the class `BaseDataStreamMarshaller` and method `createThrowable`
![image](https://github.com/user-attachments/assets/cbf66b58-7638-4032-a022-87c1a53379dc)
