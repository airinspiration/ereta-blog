---
title: "Invictus IR Labs: The Bonus Bait"
date: 2026-04-11
---

# Background
A Microsoft Defender incident has been triggered by an analytics rule matching known IOCs tied to the Scattered Spider threat group. You'll take on the role of a security analyst tasked with investigating the incident from initial detection to post-compromise activity.

# Objectives
Investigate a security incident detected by Microsoft Defender
Identify malicious behavior through analysis of the different log sources
Track actor movement and actions in the environment

## Question 1
**How many users received the internal phishing lure related to the "bonus" theme?** \
This one was quick, knowing we already have the email messages logs, I just built the following trivial query to find the answer.
<img width="800" height="500" alt="image" src="https://github.com/user-attachments/assets/6ec20f5b-64ab-422c-93a9-b4915268279e" />

## Question2
**We now know the threat actor shared a document via SharePoint. What is the full object ID (URL) of the file that was shared?**
Checking on Audit Data Sources available, answer might be likely in one of those two.
<img width="595" height="780" alt="image" src="https://github.com/user-attachments/assets/03e25aed-d77c-48c1-804e-32022cbfd83b" />


<img width="827" height="775" alt="image" src="https://github.com/user-attachments/assets/e11fb3e6-c755-486a-b4ca-b6a135ebd6c4" />

**Checking on the uploaded files we can observe that there is only one related to the "Bonus" lead given in the first question** \ 
<img width="2119" height="462" alt="image" src="https://github.com/user-attachments/assets/29dd10c1-222f-4bfb-8a1f-aab7313ff3d1" />

## Question 3
**What was the IP address used by the threat actor while performing activities on SharePoint?**
Adding as a filter the sharepoint file found inthe preivous question and extracting the ClientIP of that action, we were able to find the Source IP of the threat actor.
<img width="2105" height="630" alt="image" src="https://github.com/user-attachments/assets/9abd36a1-eb30-4f1f-9ef1-e0f59acd98af" />

That IP is tagged as VPN and associated with Malware by VT
<img width="885" height="574" alt="image" src="https://github.com/user-attachments/assets/57953fb9-c70c-415d-b103-5395a11d98e2" />

## Question 4
**What is the Object ID of the file accessed by the threat actor using the '154.47.30.133' IP address? (Note: we are not looking for .jpg or image files)**

<img width="1024" height="488" alt="image" src="https://github.com/user-attachments/assets/a29954e6-1178-4fbd-9098-1322621b3eac" />

## Question 5 
**An existing inbox rule was modified — what is the name of this inbox rule?**

From experience I know that modified inbox rules will have the Operation value of `Set-InboxRule`, leveraging that filter + the `UserId` of the compromised user,
I was able to get the name of the inbox rule 

<img width="2334" height="1160" alt="image" src="https://github.com/user-attachments/assets/d0ac6be7-ec8a-4cc9-b2f7-5ae7e447ab2a" />

## Question 6
**We asked Isabella to share a screenshot of all her mailbox rules. Notice another interesting rule in the list... From what IP address was this rule created?**

<EXPLAIN WHY IT LOOKS MALICIOUS>
<img width="2196" height="590" alt="image" src="https://github.com/user-attachments/assets/ac35fb52-0c2e-4ea0-a541-18c58bb8ffb3" />

Expanding further we can find the IP that created the rule.
<img width="1970" height="988" alt="image" src="https://github.com/user-attachments/assets/4ff4646a-344e-4215-9790-7c43b2275ccd" />

## Question 7
**What is the domain targeted in this rule, where all emails are being deleted from?**

From the explanation in the previous answer, the domain is `acme-suite.com`

## Question 8
**Interesting, all emails from this domain are being removed. According to the IT administrator, this is a company we've done business with in the past. Can you identify the email address associated with this domain?**

As it was a company that it has been doing business in the past, I started searching for any value in the `RecipientAddress` field that contains the domain, but I was unable to find anything. Then,
I tried my luck using the `SenderAddress` field and I was successful on it.
<img width="2458" height="694" alt="image" src="https://github.com/user-attachments/assets/5b3b70f8-f272-4d33-8954-e6616c0c17d3" />

## Question 9
**Isabella received a phishing email from the partner domain, which led to her account compromise.
How many other users received the same original phishing email that Isabella received?**

Checking on the timestamps, Isabella sent the malicious emails on `04/07/2026 10:50:06.232 PM` UTC. Filtering for the emails that she received in day that that aren't internal,
and by the fact that question 8 mentions that `acme-suite.com` is the domain of a company they have worked before + the fact that the TA created an inbox rule so that emails
from any address from that domain gets deleted because they could try to notify to their partners that this account has been hacked, we assume that `invoices.platform@acme-suite.com`
is the name of the account that sent the email and compromised Isabella.

<img width="2160" height="664" alt="image" src="https://github.com/user-attachments/assets/3ff60394-9396-4c72-950e-b18ebc74a2ce" />

Searching for other emails sent from that account we can observe there are indeed a couple sent.
<img width="2134" height="595" alt="image" src="https://github.com/user-attachments/assets/03951d8d-acb4-44bf-b20c-90bc92d82c32" />

## Question 10
**Isabella remembers receiving a phishing email and says she opened the link and filled in her details, thinking it was needed to secure her Microsoft
365 account. Now that we know how the threat actor gained access and some of their actions, the remaining question is: was any data stolen?
How many unique emails were accessed by the threat actor across all folders?**

Sadly for this question had to leverage the hints... and provided this query with the result. My KQL skills aren't there yet :D

<img width="1133" height="699" alt="image" src="https://github.com/user-attachments/assets/518f7fef-e39d-4b88-9f3e-a149c6890eaa" />
