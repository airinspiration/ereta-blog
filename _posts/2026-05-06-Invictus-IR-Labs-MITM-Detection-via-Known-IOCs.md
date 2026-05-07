---
title: "Invictus IR Labs: Defender - Man-in-the-Middle, Detection via Known IOCs (Medium)"
date: 2026-05-16
---

# Background
A Microsoft Defender incident has been triggered by an analytics rule matching known IOCs tied to the Scattered Spider threat group. You'll take on the role of a security analyst tasked with investigating the incident from initial detection to post-compromise activity.

# Objectives
* Investigate a security incident detected by Microsoft Defender
* Identify malicious behavior through analysis of the different log sources
* Track actor movement and actions in the environment

# Question 1
**An incident has been triggered in Microsoft Defender, and you are assigned to investigate it. What is the name of the incident?**
<img width="2419" height="578" alt="image" src="https://github.com/user-attachments/assets/14563ab5-f51d-4ef1-8fbe-ae9b9e8c31b7" />

# Question 2
**By what sort of rule was this incident triggered?**
Checking within the alerts, we can see that it is an analytics rule.
<img width="1985" height="1156" alt="image" src="https://github.com/user-attachments/assets/f27bd735-e246-428c-a0a9-034fa7ee2498" />

# Question 3
**What are the MITRE ID's assigned to the incident? (Answer format TXXXX,TXXXX)** \
We can get the technique IDs from the alerts
<img width="1128" height="945" alt="image" src="https://github.com/user-attachments/assets/dc4b72d6-dbcb-4f3e-be37-17bfe31c41e2" />

# Question 4
**Which user was involved in the activity that triggered the analytics rule?**

Checking under the "Assets" tab, we can observe the unique user involved.
<img width="958" height="666" alt="image" src="https://github.com/user-attachments/assets/c55fb9ad-d1b2-4f70-bb45-c219cabb12db" />

# Question 5
**Which IP addresses are associated with the user activity that triggered the incident? (Answer format: IP1,IP2)**

We can get the IOCs involved under the "Evidence and Response" tab
<img width="1138" height="486" alt="image" src="https://github.com/user-attachments/assets/89b59444-849d-42ab-bdcc-73bdfec0b604" />

# Question 6
**Let's find out more about the logins, from which country are the IP addresses originating? (Answer format: Country code, e.g., NL)**

Querying for sign in logs from the associated ip addresses, and deduplicating the country code, we were able to get it.
<img width="638" height="497" alt="image" src="https://github.com/user-attachments/assets/6a87391c-0bed-4bc4-9c4f-98041cce5410" />

# Question 7
**Examine the first login originating from the IP addresses you identified earlier. What was the name of the Microsoft service or portal that was accessed during that login?**

By leveraging `arg_min()` to get the first (oldest) log, we can see which app the attacker first logged into. Which that app is known
to be commonly used to redirect to after a user has been a victim of an AiTM atack. 
<img width="627" height="502" alt="image" src="https://github.com/user-attachments/assets/6b460d86-b47a-494a-914c-101e238aed4e" />

# Question 8
**Interesting, this behavior is often associated with man-in-the-middle attacks, what is the session ID associated for this activity?**

As I mentioned before, a login to this app is standard AiTM. So we just need to display the `SessionId` field as well.
<img width="604" height="394" alt="image" src="https://github.com/user-attachments/assets/58c7a934-4df6-4c48-b91b-496713fe5eb1" />

# Question 9
**Since this session is likely to have been hijacked during the adversary-in-the-middle attack, what is the first IP that is logging in for this session?**

As this session was hijacked (meaning that the user logged in legitimaly and then the TA logged in with the stolen token, by removing the
filter specifying the IPAddresses the TA used to login from, we are able to get the user IP.
<img width="601" height="406" alt="image" src="https://github.com/user-attachments/assets/ad9d44c6-8c89-4feb-89c3-e420845d0e17" />

# Question 10
**Keeping the filter on the session ID, what user-agent was used by the attacker?**

By getting all different values in the `UserAgent` field, we can see that the user has only used a single UA. Which seems to be Firefox on Linux
<img width="688" height="427" alt="image" src="https://github.com/user-attachments/assets/79c28b8d-2ec6-497e-989b-56491606a404" />

<img width="1162" height="506" alt="image" src="https://github.com/user-attachments/assets/c37d5ee1-49df-4335-b096-7e81463aabbb" />

# Question 11
**What was the first application-related action performed by the threat actor after logging in? (Answer format, ActivityDisplayName)"**
