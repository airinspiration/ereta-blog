---
title: "Invictus IR Labs: Azure - Foothold via OAuth (Medium difficulty)"
date: 2026-05-10
---

# Background
A recent blog post highlights how threat actors are leveraging a malicious OAuth application (93600841-445a-4cc0-9de1-3fd50fb31b2e) to gain a foothold in Azure environments.
Your task is to investigate whether our environment has been affected and analyze any suspicious OAuth applications.

# Objectives
* Investigate suspicious OAuth applications in the Azure environment
* Identify potentially malicious applications and their permissions
* Analyze application characteristics that may indicate malicious intent

# Question 1
**Threat intelligence reporting has highlighted that threat actors are leveraging the malicious OAuth application 93600841-445a-4cc0-9de1-3fd50fb31b2e to gain a foothold in Azure environments. What is the name of this application?**

Looking at the `OAuthApps_CL` table schema, we can see a field called `AppID`, which seems to be what we are looking for.
![image](https://github.com/user-attachments/assets/5fb92509-6a0c-40f7-8d76-bebac5d4b450)

Searching for the value in that field, we can get the name of the malicious app.
![image](https://github.com/user-attachments/assets/8e6df50f-8d73-4bbb-b9c8-27d2499a93f4)

# Question 2
**How many unique permissions related to Mail does this application have?**

Getting the values that contain `Mail` and deduplicating them leveraging `dcount()`, we can get the number of unique permissions.

![image](https://github.com/user-attachments/assets/1d9dc04e-7f44-4dc1-a555-83017e359996)

# Question 3
**What type of permissions does this application have?**

By displayinh the values in `PermissionType`, we can get the type of permission this app has, which in this case is `Delegated`. This means that is acting
on behalf of a user, thus, a user gave permission to his account likely through phishing. Read more about it [here](https://learn.microsoft.com/en-us/entra/identity-platform/permissions-consent-overview#delegated-access-access-on-behalf-of-a-user).

![image](https://github.com/user-attachments/assets/fbe7faca-e905-4737-8fe9-0bab7a0502d9)

# Question 4
**Threat intelligence reports note that attackers sometimes use very short or non-alphanumeric names to make their malicious OAuth applications less
noticeable. What is the name of the application that matches this attacker behavior?**

Leveraging regex `^[^a-zA-Z0-9]+$`, we can find the app that doesn't contain alphanumeric chars.
![image](https://github.com/user-attachments/assets/f4780972-792c-4db9-b69a-8c1cc43b322f)

# Question 5
**Is this application visible to users in the tenant? (Answer format Yes/No)**

Displaying the `ApplicationVisibility` field, we can see that the app is not visible for users in the tenant.
![image](https://github.com/user-attachments/assets/dd9ac4fa-4c03-48d7-ad4c-a396c5fb6db2)

# Question 6
**Which Delegated permissions does this application have?**

Out of the three results we got in the last question, when looking into the single log that has `Delegated` set in `PermissionType`, we can get the delegated permission.
![image](https://github.com/user-attachments/assets/8dadbfb4-4d03-4368-b692-747ee314a104)

# Question 7
**An OAuth application was registered with suspicious redirect URIs that could facilitate token theft. What is the Object ID of this application?**

Going through the deduplicated redirect URI's, one stands out given its path being `gettoken` which reads as it could facilitate token theft.
![image](https://github.com/user-attachments/assets/5c705b15-d281-4ab2-9082-8bcdfb168c70)

Filtering by that value and deduping the `ClientObjectId` field, we can get the Object ID of the other malicious app.
![image](https://github.com/user-attachments/assets/993fd2d5-62e5-4f88-b392-0e65a6095e45)

# Question 8
**What is the name of the application associated with the user ID 16451291?**

The question states that the user ID is a 8 digit number, but that's not the format of entra user IDs (e.g. `a23f765f-8afa-4b4a-8287-a5cf3513b971`).
I did a free search looking for that string and that value corresponds to the `PrincipalDisplayName` field. We can observe there is only one app associated
with that user.

![image](https://github.com/user-attachments/assets/04998411-7b09-4158-875a-4787e3eb38ea)
