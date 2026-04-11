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
This one was quick, knowing we already have the email messages logs, I just built the following trivial query to find the answer. \

<img width="800" height="500" alt="image" src="https://github.com/user-attachments/assets/6ec20f5b-64ab-422c-93a9-b4915268279e" />

## Question 2
**We now know the threat actor shared a document via SharePoint. What is the full object ID (URL) of the file that was shared?** \
Checking on Audit Data Sources available, answer might be likely in one of those two.

<img  width="595" height="780" alt="image" src="https://github.com/user-attachments/assets/03e25aed-d77c-48c1-804e-32022cbfd83b" />

Given a document was shared, it had to be uploaded, so this event should help us figuring out what was it.
<img width="827" height="775" alt="image" src="https://github.com/user-attachments/assets/e11fb3e6-c755-486a-b4ca-b6a135ebd6c4" />

Checking on the uploaded files we can observe that there is only one related to the "Bonus" lead given in the first question

<img width="2119" height="462" alt="image" src="https://github.com/user-attachments/assets/8a467331-3067-4892-a210-2746285bd7d0" />


## Question 3
**What was the IP address used by the threat actor while performing activities on SharePoint?** \
Adding as a filter the sharepoint file found inthe previous question and extracting the ClientIP of that action, we were able to find the Source IP of the threat actor.

<img width="850" height="630" alt="image" src="https://github.com/user-attachments/assets/9abd36a1-eb30-4f1f-9ef1-e0f59acd98af" />

That IP is tagged as VPN and associated with Malware by VT

<img width="885" height="574" alt="image" src="https://github.com/user-attachments/assets/57953fb9-c70c-415d-b103-5395a11d98e2" />

## Question 4
**What is the Object ID of the file accessed by the threat actor using the '154.47.30.133' IP address? (Note: we are not looking for .jpg or image files)**
Filtering by the `FileAccessed` Sharepoint Operation value + with the known IP + excluding jpg files, we are able to get the file the TA accessed.

<img width="1024" height="488" alt="image" src="https://github.com/user-attachments/assets/a29954e6-1178-4fbd-9098-1322621b3eac" />

## Question 5 
**An existing inbox rule was modified — what is the name of this inbox rule?**

From experience I know that modified inbox rules will have the Operation value of `Set-InboxRule`, leveraging that filter + the `UserId` of the compromised user,
I was able to get the name of the inbox rule.

<img width="2334" height="1160" alt="image" src="https://github.com/user-attachments/assets/d0ac6be7-ec8a-4cc9-b2f7-5ae7e447ab2a" />

## Question 6
**We asked Isabella to share a screenshot of all her mailbox rules. Notice another interesting rule in the list... From what IP address was this rule created?**

If you look at the value of the `Name` field, it has two dots as a name, which has been one of the most (if not the most) common names in BEC cases, I myself have seen it being used in real BEC compromises. Also notice that it tries to delete the emails coming from any account from the domain `acme-suite.com`, which is not just a shot in the dark the TA is doing, but it is likely that an account from this tenant was used to compromise this user and wants to avoid the user being able to read any email from it in case they want to notify their email partners.
  
<img width="2196" height="590" alt="image" src="https://github.com/user-attachments/assets/ac35fb52-0c2e-4ea0-a541-18c58bb8ffb3" />

Expanding further we can find the IP that created the rule.

<img width="1970" height="988" alt="image" src="https://github.com/user-attachments/assets/4ff4646a-344e-4215-9790-7c43b2275ccd" />

## Question 7
**What is the domain targeted in this rule, where all emails are being deleted from?** \

From the explanation in the previous answer, the domain is `acme-suite.com`

## Question 8
**Interesting, all emails from this domain are being removed. According to the IT administrator, this is a company we've done business with in the past. Can you identify the email address associated with this domain?** \

As it was a company that it has been doing business in the past, I started searching for any value in the `RecipientAddress` field that contains the domain, but I was unable to find anything. Then, I tried my luck using the `SenderAddress` field and I was successful on it.

<img width="2458" height="694" alt="image" src="https://github.com/user-attachments/assets/5b3b70f8-f272-4d33-8954-e6616c0c17d3" />

## Question 9
**Isabella received a phishing email from the partner domain, which led to her account compromise.
How many other users received the same original phishing email that Isabella received?**

Checking on the timestamps, Isabella sent the malicious emails on `04/07/2026 10:50:06.232 PM` UTC. Filtering for the emails that she received in day that that aren't internal, and by the fact that question 8 mentions that `acme-suite.com` is the domain of a company they have worked before + the fact that the TA created an inbox rule so that emails from any address from that domain gets deleted because they could try to notify to their partners that this account has been hacked, we assume that `invoices.platform@acme-suite.com` is the name of the account that sent the email and compromised Isabella.

<img width="2160" height="664" alt="image" src="https://github.com/user-attachments/assets/3ff60394-9396-4c72-950e-b18ebc74a2ce" />

Searching for other emails sent from that account we can observe there are indeed a couple sent.

<img width="2134" height="595" alt="image" src="https://github.com/user-attachments/assets/03951d8d-acb4-44bf-b20c-90bc92d82c32" />

## Question 10
**Isabella remembers receiving a phishing email and says she opened the link and filled in her details, thinking it was needed to secure her Microsoft
365 account. Now that we know how the threat actor gained access and some of their actions, the remaining question is: was any data stolen?
How many unique emails were accessed by the threat actor across all folders?**

Sadly for this question had to leverage the hints... and provided this query with the result... Given my little experience with KQL + it was already midnight when I was answering this question sadly I gave up :|

<img width="1133" height="699" alt="image" src="https://github.com/user-attachments/assets/518f7fef-e39d-4b88-9f3e-a149c6890eaa" />

## Question 11
**Unfortunately, this wasn't the only way the threat actor accessed emails. They registered a well-known application used for data exfiltration. What is the name of this application?**

The question makes it sound as if the attacker registered a malicious oauth application ([T1671](https://attack.mitre.org/techniques/T1671/)). Data exfiltration would be performed by creating an oauth app that has the `Mail.Read` permissions for "Thunderbird" it would allow the TA to receive the emails of the user that granted the consent.

Checking on all the `Operation` values available in the `AzureActiveDirectory`, we can observe that the `Consent to application` event could tell us something.

<img width="778" height="1000" alt="image" src="https://github.com/user-attachments/assets/53ab5a94-7c01-4c4f-a920-b78a3c8fdef3" />

Going through the log, we got no name of the application, but we got a ServicePrincipal ID which could help us get some extra information on the OAuth Path.

<img width="2114" height="1058" alt="image" src="https://github.com/user-attachments/assets/5b0721ca-3b13-4a28-a1ee-ddc9f2150460" />

> 💡A ServicePrincipal object is created when an OAuth App gets created because the app needs to be represented by a security principal in order to be able to access resources within the tenant.

Filtering why the `Add service principal.` events + by the Service Principal ID, we only got one log, which then we were able to extract the display name of the malicious OAuth App.

<img width="1271" height="633" alt="image" src="https://github.com/user-attachments/assets/5aefd208-cd2b-4eef-a36a-552ef048d07c" />

This was not asked, but we can also get the scope of permissions given to the oauth app. As we can observe there are several of them including able to modify the mails/mailbox item, access to calendar, contacts and user data. Notice the presence of `offline_access`, which allows the oath app to get a refresh token to get persistent access and not only an access token which would be available for around an hour.

<img width="1948" height="653" alt="image" src="https://github.com/user-attachments/assets/fb382328-ff64-4977-8f45-a8ded49562ac" />

