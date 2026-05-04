---
title: "Storm Catcher: BEC in Microsoft 365"
date: 2026-05-03
---

# Background
During a routine DLP sweep, your organization's compliance team detects a high-severity spike of mailbox deletions combined with unusual forwarding rules inside the IT and finance department. Within minutes, IT responds by resetting credentials and terminating active sessions for the affected accounts.

But there's a twist: the mailbox owners claim they did not delete or forward any emails. At the same time, threat intelligence identifies several indicators of compromise (IoCs) that align with known tactics from a business email compromise (BEC) campaign conducted by a group called Storm-1167.

Now it's your turn. Step into the role of an incident responder and figure out what happened.

# Objectives
Identify signs of account compromise in Microsoft 365
Trace the origin and actions of potentially malicious actors
Determine what data may have been compromised

# Question 1
**Who is the user whose mailbox shows a sudden spike in deletions? (Provide the User Principal Name, e.g., user@domain.com)**

So... we where given a plenty amount of logs sources for this case, so looking at the different `AuditLogRecordType` values, as we want to know of email deletions, the record type should be related to exchange, so we have 4 possibilities.

![image](https://github.com/user-attachments/assets/220e2fe4-934b-4102-b4d6-20247a68f483)

Checking on the [0365 API schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema), we can see the description of each record type, which allows us to know that we need to look into the `ExchangeItemGroup` type, as we want to get email deletions.
![image](https://github.com/user-attachments/assets/fc59ae42-f97a-4f73-b202-0cc313ffeb24)

Once filtering with the `ExchangeItemGroup` record type, we can observe that there are three different types of deletion. For further details, look into [this](https://learn.microsoft.com/en-us/compliance/assurance/assurance-exchange-online-data-deletion) Microsoft documentation page.

![image](https://github.com/user-attachments/assets/f7f4536e-2c3c-47d9-97ed-e607fd814ae9)

There's no further filtering we need to do as we only have `Operation` values related to deletion events. So we just need to count for the amount of events per user and that way we can get the answer.
![image](https://github.com/user-attachments/assets/b10614ed-b3e5-4889-9f1b-b49441e18e0a)

# Question 2
**Which IP address was responsible for the majority of the mailbox deletion events?**

By filtering for the events for the user with the spike of email deletions, and counting the events by the ClientIP that requested them (after unpacking the `AuditData` field), we are able to see what IP caused the majority of events.
![image](https://github.com/user-attachments/assets/320bfa31-5982-4ba0-aabf-ccc3ee5811e)

# Question 3
**The IT administrator observed multiple MoveToDeletedItems events for the user. How many emails were permanently deleted by the threat actor**

By permanently deleted, we know that it's referring to `HardDeleted` items. Filtering by that Operation for the user `owen.k@tenxfintech.com` we are able to know the total amount of permanently deleted emails.

![image](https://github.com/user-attachments/assets/ea4f4f37-8fc4-4973-a04a-d18348eb1673)

# Question 4
**What application was used by the attacker to read the emails?**

Looking at the `Consent to Application.` events of the user `owen.k@tenxfintech.com`, and extracting the corresponding `ModifiedProperties` (that contains mainly app permissions/scope given to the tenant, values extracted - shown in `ConsentType` and `Scope` columns) and `ExtendedProperties` (that contains information about the application that was given the permissions by the user - shown in column `OauthAppId`). We can observe that the `AppId` value corresponds to the _eM Client_ app, according to [Huntress](https://huntresslabs.github.io/rogueapps/#:~:text=A%20robust%20email,financial%20transaction%20fraud.), it is "A robust email client often leveraged by attackers due to its extensive capabilities. eM Client allows attackers to sync multiple inboxes into the same client, download all emails from an inbox, mass mail spam, export calendars and contacts, and create inbox rules to stage financial transaction fraud.". \
Additionally, we can observe that the `EWS.AccessAsUser.All` permission can allows the app to have access to all mailboxes in the tenant, which can also be noticed in the `AllPrincipals` value within the `ConsentType` column.

Note: ChatGPT was leveraged to quickly create regex to get the different fields retrived here
![image](https://github.com/user-attachments/assets/9a2979e9-5db2-461d-a217-6c32c204beaf)

# Question 5
**The threat actor used the application eM Client to access emails, how many events were generated because of this activity?**

Every `MailItemAccessed` log contains the information of the client that accessed the email/s in the field `ClientAppId`. Having knowledge of which is the AppId of the _em Client_ app, we can filter for only the emails that contain that value in the `ClientAppId` field.

![image](https://github.com/user-attachments/assets/e261cc0b-6de5-47b8-9238-1db2ade7614a)

# Question 6
**The threat actor removed security alerts from the inbox of Owen. What is the subject of one of the emails that was generated in relation to eDiscovery abuse?**

As we don't know which type of deletion was leverage by the threat actor, we are going leave the search open by not specifying a `Operation` value. Then, we will extract the subject for each event and look for any that contains the word "eDiscovery".
![image](https://github.com/user-attachments/assets/43a03abc-1836-4e62-90a7-aa7a9011f517)

# Question 7
**The threat actor started a search looking for credentials. What is the full search query used?**

As I have never worked with the _eDiscovery_ ("_Discovery_" in UAL), I got myself a bit familiarized with it using the [Audit Log Activities](https://learn.microsoft.com/en-us/purview/audit-log-activities) documentation from MS Learn.

Looking at the operations that could be related to searches, we are likely looking for any of the following, where they all starts with "PurviewSearch" 
![image](https://github.com/user-attachments/assets/a8f183af-dc54-4a49-bed2-deb7cb71b90d)

Looking at the fields we can observe that there is one that contains the query text.
![image](https://github.com/user-attachments/assets/49c36564-da29-4e81-9cfb-866ab13a2f64)

Removing empty values, we can get the search query used.
![image](https://github.com/user-attachments/assets/86385a96-c8fd-474d-85fc-e285ab7bdd8a)

# Question 8
**The threat actor was removed before they could download the eDiscovery results. However, it's still necessary to determine how Owen Kelly's account was initially compromised. 
Owen Kelly remembers receiving an email from a colleague in relationship to DocuSign, but he remembers the link not working and the colleague who allegedly sent it claims they never sent it. Who is the user that sent the phishing email to Owen Kelly?**

We can observe the email that the user `harper.j` sent to Owen with a common Docusign theme email requesting the recipient signature.
![image](https://github.com/user-attachments/assets/78febe56-a10b-4928-97a4-928a5ae0b288)

# Question 9
**We recovered the following domain from the phishing email sent to Harper James: https[://]login[.]account-notice-noreply[.]com \
What is the IP address of this domain?**

Checking in VT, we can get the IP of the domain.
![image](https://github.com/user-attachments/assets/8f253eca-d933-4a44-8f99-12ecbe09839f)

# Question 10
**After identifying that harper.j@tenxfintech.com was compromised, examine the Message Trace logs to determine the likely lure email that led to the compromise. What was the subject line of this email?**

While reviewing the emails sent to harper, we can observe that there is one with the subject being "Account Verification Required" which sounds like a possible lure. We can confirm that is the malicious email sent as when checking the IP in VT it is linked with phishing activity.
![image](https://github.com/user-attachments/assets/5f29cdff-c7e0-4a90-9fe7-0f50f896707e)

![image](https://github.com/user-attachments/assets/da601795-991d-4f0a-b663-704cc7d62d48)

# Question 11
**Here is the screenshot of the phishing email. Identify the session ID for the login that has resulted in the compromise.**

As the phishing method was through device code phishing, we can observe the successful login that happened once the user inserted the MFA code (we know this due to the existance of value `OATH verification code` in the _MfaDetail_ column. Then we can see that in the same sessionId the threat actor accessed multiple apps for the user such as `OfficeHome`, `Azure Portal`, `Teams` and `Outlook`.
![image](https://github.com/user-attachments/assets/679dfc97-ca47-4c0a-b9a3-35ca681189a9)

# Question 12
**With device code authentication, the attacker only had an OAuth token and could not use the Outlook GUI. To access emails, the threat actor relied on the Microsoft Graph API. Which Graph API request did they make to enumerate or read the inbox messages? (Answer format: RequestUri)**

First I went into checking how a graph api path is when attempting to read inbox messages, and I got to [this](https://learn.microsoft.com/en-us/graph/api/mailfolder-list-messages?view=graph-rest-1.0&tabs=http) resource.
Basically they would follow the format in the screenshot below.
![image](https://github.com/user-attachments/assets/0a6c87dd-dd64-46f9-8544-07d46aae1312)

By filtering by the session id found in the past question that resulted in the login from the threat actor and by looking for any references of the user harper wihtin the `RequestUri` field, we know the exact path leveraged to list her emails.
![image](https://github.com/user-attachments/assets/66331c50-66d1-4d4c-b41f-b3fe807af3b0)

# Question 13
**From what region were those actions performed?**

From the same query we know that it was done from `Southeast Asia`
![image](https://github.com/user-attachments/assets/ae20f2fc-1443-4b69-b47d-a53b045074ac)

# Question 14
**Which SharePoint site did the attacker target?**

Looking for logs that contain `SharePoint` within the `RequestUri` we found that it was targeting the Finance sharepoint.
![image](https://github.com/user-attachments/assets/e2153f5f-ec8f-4014-b457-9e147309e367)

# Question 15
**How much data was exfiltrated from the SharePoint of harper.j@tenxfintech.com? (answer in bytes)**

As it talks about data exfil on the Finance site, it was implicitly referring to SharePoint `FileDownloaded` events. It was quite tricky, as I was getting the answer incorrect when counting the total amount of file downloaded events for that site, then I was checking on the different fields and notice that there are different values for user agent. The first one seems related yo sync activites of one drive and the last one I checked it and is a legit macos user agent. The middle one caught my attention as it contained the "powershell" string in it.
![image](https://github.com/user-attachments/assets/1ae6c1ad-5f2d-4167-b385-b3b010d5e58d)

Once filtering by the user agent with "powershell" in it, we can observe that the threat actor grabbed mostly financial related data.
![image](https://github.com/user-attachments/assets/c7a4660f-658b-4fc6-bab1-01b90268627f)

Last, we can proceed to count the total amount of bytes for each event.
![image](https://github.com/user-attachments/assets/3db33ae9-6878-4f0f-b58c-6bf095b6ddd8)

# Question 16
**Security-related emails such as account lockout notifications and verification codes never reached the intended user. What is the name of the inbox rule responsible for intercepting these critical security messages?**

Looking for the email rules in harper's inbox, we can observe that there is one that looks for emails where the subject contains any of `password reset, account verification, security alert, suspicious activity, malware detected, unauthorized access`.
![image](https://github.com/user-attachments/assets/375bc678-70a9-4617-9c11-4f3a11a87800)

# Question 17
**The threat actor also set up a rule that required elevated privileges. What's the name of this rule?**

I wasn't pretty sure about this one, as user inbox rules don't require elevated privs, so this should be then related to transport rules that function as a inbox rule but for all emails received by the tenant.
Checking for that event, there is only once instance and the rule was created by Owen.
![image](https://github.com/user-attachments/assets/d01cee40-7399-4747-ad33-fde86bb28f22)

# Question 18

**While Harper James' account was phished and the attacker gained Graph API access via device code authentication, they could not use the Outlook GUI. Instead, they abused the Graph API to send phishing emails directly. However, Harper's account wasn't the only one. Another compromised user also sent an email via Graph. Which user account was it? (Answer format: User Principal Name, e.g., user@domain.com)**

Through the GraphAPI, users can sent emails from their account leveraging POST /me/sendMail ([MSFT docs](https://learn.microsoft.com/en-us/graph/api/user-sendmail?view=graph-rest-1.0&tabs=http#:~:text=Copy-,POST%20/me/sendMail,-POST%20/users/%7Bid)).

By searching for any graphapi calls that were made to that path + correlating the sessionId with the SignIn table, we were able to get the other compromised user.

![image](https://github.com/user-attachments/assets/cc5be708-375d-491e-a103-66df90d87b0b)

# Question 19
**According to Microsoft, most risky activities were remediated. However, one user is still marked as at risk. What is the user principal name of this user?**

Seraching in the risky events table, and removing the remediated events, we got the user still at risk.
![image](https://github.com/user-attachments/assets/e6ce144c-d9ab-42f8-a7f2-5f9c74b97f9f)

# Question 20
**Interesting, this user might also be compromised. Emails are being forwarded to an external address. What is this address?**

By getting the mailbox rules and getting only the rules that contain a value in the `ForwardTo` field we were able to get the malicious rule created.
![image](https://github.com/user-attachments/assets/b97a0ecd-bfd1-4b2f-9d9d-0f24db8a39bb)

# Question 21
**When resetting the password, settings, and MFA devices for the compromised accounts, the administrator noticed a strange email address being used to persist via MFA. What email address did they add to receive MFA codes?**

From experience, when any property of a user is modified, it is going to be reflected in the `Updated user` Operation. Having knowledge of this I filtered by the known compromised users, and as the question mentions an email address used to receive MFA codes, I searched for any `modified properties` that contained the `@` char. As we can observe that address is the one that initally compromised `henry.j`
![image](https://github.com/user-attachments/assets/e4acbd9d-cabe-4593-99ef-c3b353073a80)

