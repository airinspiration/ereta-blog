---
title: "BlueSky Ransomware Lab"
date: 2025-06-14
---

# Scenario
A high-profile corporation that manages critical data and services across diverse industries has reported a significant security incident. Recently, their network has
been impacted by a suspected ransomware attack. Key files have been encrypted, causing disruptions and raising concerns about potential data compromise. Early signs
point to the involvement of a sophisticated threat actor. Your task is to analyze the evidence provided to uncover the attacker’s methods, assess the extent of the
breach, and aid in containing the threat to restore the network’s integrity.

# Questions
### **1. Knowing the source IP of the attack allows security teams to respond to potential threats quickly. Can you identify the source IP responsible for potential port scanning activity?**
R= 87.96.21.84

Leveraging the [Endpoints](https://www.wireshark.org/docs/wsug_html_chunked/ChStatEndpoints.html) window, we can notice that `87.96.21.81` and `87.96.21.84` with a total of 4,767 packets, where `.84` has more than twice
the packets being sent compared to `.81`, which could be an indicator that `.84` was the one performing the port scanning.
![image](https://github.com/user-attachments/assets/d4f079b5-3df1-4684-aea0-5db489c89497)

If we filter the packets by showing only the ones where `.84` started the conversation, we can observe that it sending `SYN` packets to a bunch of known ports as they are marked with the bright green using a coloring rule I've created.
As we can observe at the bar further to the right, there's lots of them.
![image](https://github.com/user-attachments/assets/72ec573a-9f49-4b9b-9900-4ac10eb20fad)
![image](https://github.com/user-attachments/assets/8346de3c-e98b-4018-9bfc-2c0e865af885)


Using the filter `tcp.flags.syn == 1` to only get `SYN` request packets, we can observe that `.84` has been the one performing the port scanning.
![image](https://github.com/user-attachments/assets/e80986a0-c723-49c8-8784-1ce97237d0b1)

### **2. During the investigation, it's essential to determine the account targeted by the attacker. Can you identify the targeted account username?**
R= sa

First, I went straight into the Windows Event Logs, just to get a feel of what I could find using [chainsaw](https://github.com/WithSecureLabs/chainsaw). Using looking at the output of following command
`./chainsaw hunt -s sigma/rules/ --mapping mappings/sigma-event-logs-all.yml -r rules/ BlueSkyRansomware.evtx`, I noticed that there were quite a bunch of sigma detections that were triggered. With no indicator of which account was used,
we can pivot to the network logs and see for [Tabular Data Stream](https://en.wikipedia.org/wiki/Tabular_Data_Stream) traffic.

![image](https://github.com/user-attachments/assets/bdb3823c-377e-496d-808b-bea0ecbe25d8)

Looking at the `Protocol Hierarchy` window, we can observe that there's indeed `TDS` traffic, where we'd first need to confirm that there's a type of message that indicates a login.
![image](https://github.com/user-attachments/assets/8f284b07-a74d-4000-a9e2-c726de65569e)

Checking over the [MSFT TDS Protocol Specification](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/b46a581a-39de-4745-b076-ec4dbb7d13ec?redirectedfrom=MSDN), there are two type of messages that
could potentially contain a username. After reading a bit of the `Pre-Login` message type, it is used to agreed on the parameters used for the connection, which should come before the user login.
![image](https://github.com/user-attachments/assets/b803d176-4f9c-4d87-be4b-3f0f7844a434)

The `Login` message type does specify a `username` field, and when comparing it with a Wireshark `TDS7 Login Packet` we can indeed confirm its structure, indicating that the username used to login to the SQL Server was `sa`.
![image](https://github.com/user-attachments/assets/3a00aff2-d631-485e-9d3d-39009bb3b9f5)

### **3. We need to determine if the attacker succeeded in gaining access. Can you provide the correct password discovered by the attacker?**
R= cyb3rd3f3nd3r$

When following the `TCP stream` of the login, we can observe that a `SQL Batch` message type packet is seen afterwards (packet 2643), which means that there was a set of SQL statements submitted to the database server for execution, 
and that the server replied with a response (packet 2645). But I got interested on if there was anything in the server `Response` packet, that indicated explicitely if the connection was successful.
![image](https://github.com/user-attachments/assets/fcedbf0a-fefd-4c62-b78a-5735bb716b61)

After skimming through the contents of the `Response packet`, there was nothing that acknowledged the connection being established.

![image](https://github.com/user-attachments/assets/f32c7415-a921-4c5c-a3ab-7f85a91a6b0a)

I got particularly interested in the `LoginAck` Data Token Stream Packet, when reading through its details in the protocl reference, it states that `If a LOGINACK is not received by the client as part of the
login procedure, the login to the server is unsuccessful.`. Having knowledge of this, we can confirm the login was successful as there's a "LoginAck" within the Response packet.
![image](https://github.com/user-attachments/assets/f65005f4-b6b8-4cd9-858c-e4f79abea358)

The password used can be found is `cyb3rd3f3nd3r$`.
![image](https://github.com/user-attachments/assets/efeef9cf-5566-47ba-8351-54b9bff9938b)

### **4. Attackers often change some settings to facilitate lateral movement within a network. What setting did the attacker enable to control the target host further and execute further commands?**
R= 

Checking the contents of the `SQL Batch` packet, the threat actor enabled `xp_cmdshell` by using `EXEC sp_configure 'xp_cmdshell'`, which is known to be
[leveraged by threat actors](https://attack.mitre.org/techniques/T1059/003/#:~:text=Team%20used%20the-,xp_cmdshell,-command%20in%20MS) as part of their compromises.

![image](https://github.com/user-attachments/assets/d536f6ae-2ab9-4e5e-a195-8d7e0524d980)

