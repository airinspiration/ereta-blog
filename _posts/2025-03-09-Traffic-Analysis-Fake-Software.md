---
title: "TRAFFIC ANALYSIS EXERCISE: DOWNLOAD FROM FAKE SOFTWARE SITE"
date: 2025-03-09
---

# BACKGROUND
You work as an analyst at a Security Operation Center (SOC). Someone contacts your team to report a coworker has downloaded a suspicious file after searching for Google Authenticator. The caller provides some information similar to social media posts at:

https://www.linkedin.com/posts/unit42_2025-01-22-wednesday-a-malicious-ad-led-activity-7288213662329192450-ky3V/
https://x.com/Unit42_Intel/status/1882448037030584611
Based on the caller's initial information, you confirm there was an infection.  You retrieve a packet capture (pcap) of the associated traffic.  Reviewing the traffic, you find several indicators matching details from a Github page referenced in the above social media posts.  After confirming an infection happened, you begin writing an incident report.

## LAN SEGMENT DETAILS FROM THE PCAP
**LAN segment range**:  10.1.17[.]0/24   (10.1.17[.]0 through 10.1.17[.]255) \
**Domain**:  bluemoontuesday[.]com \
**Active Directory (AD) domain controller**:  10.1.17[.]2 - WIN-GSH54QLW48D \
**AD environment name**:  BLUEMOONTUESDAY \
**LAN segment gateway**:  10.1.17[.]1 \
**LAN segment broadcast address**:  10.1.17[.]255

# Questions

**1. What is the IP address of the infected Windows client?** \
R= 10.1.17.215

From what was reported (phishing through "google authenticator" impersonation site, we can see the IP `10.1.17.215` connecting to the suspected site
> Filter used: `(http.request or tls.handshake.type eq 1) and !(ssdp)`

![image](https://github.com/user-attachments/assets/2dfb4eb9-aeb3-41c4-817d-bcdfd4969ba1)


**2. What is the mac address of the infected Windows client?** \
R= 00:d0:b7:26:4a:74

Looking into the ethernet frame, we can get its mac
![image](https://github.com/user-attachments/assets/a62efd26-30ae-40ab-9573-d5965ba9ee4d)

**3. What is the host name of the infected Windows client?** \
R= DESKTOP-L8C5GSJ

The `NETBIOS`protocol, allows us to know the hostname of the device
![image](https://github.com/user-attachments/assets/c079a82f-6c7e-4525-ad10-07175428eb44)

**4. What is the user account name from the infected Windows client?** \
R= shutchenson

Looking into the `Protocol Hierarchy` Statistics, I determined that the `Kerberos` protocol will give us a username.
![image](https://github.com/user-attachments/assets/145b224b-90bb-4fbe-88ec-8cf4300abd8d)

The identity is located in the `CNameString` field.
![image](https://github.com/user-attachments/assets/59e158cf-9048-4008-af62-397e741b43df)

**5. What is the likely domain name for the fake Google Authenticator page?** \
R= google-authenticator.burleson-appliance.net

From the threat intel given in the _Background_ section, the malicious sites were under the domain `burleson-appliance.net`. As shown in Q1,
there's a site called `google-authenticator.burleson-appliance.net`, which matches what was previously seen.
