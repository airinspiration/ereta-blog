---
title: "Storm Catcher: BEC in Microsoft 365"
date: 2026-04-20
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

<img width="611" height="1062" alt="image" src="https://github.com/user-attachments/assets/220e2fe4-934b-4102-b4d6-20247a68f483" />

Checking on the [0365 API schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema), we can see the description of each record type, which allows us to know that we need to look into the `ExchangeItemGroup` type, as we want to get email deletions.
<img width="2056" height="1080" alt="image" src="https://github.com/user-attachments/assets/fc59ae42-f97a-4f73-b202-0cc313ffeb24" />

Once filtering with the `ExchangeItemGroup` record type, we can observe that there are three different types of deletion. For further details, look into [this](https://learn.microsoft.com/en-us/compliance/assurance/assurance-exchange-online-data-deletion) Microsoft documentation page.

<img width="647" height="516" alt="image" src="https://github.com/user-attachments/assets/f7f4536e-2c3c-47d9-97ed-e607fd814ae9" />

There's no further filtering we need to do as we only have `Operation` values related to deletion events. So we just need to count for the amount of events per user and that way we can get the answer.
<img width="586" height="671" alt="image" src="https://github.com/user-attachments/assets/b10614ed-b3e5-4889-9f1b-b49441e18e0a" />

# Question 2
**Which IP address was responsible for the majority of the mailbox deletion events?**

By filtering for the events for the user with the spike of email deletions, and counting the events by the ClientIP that requested them (after unpacking the `AuditData` field), we are able to see what IP caused the majority of events.
<img width="1052" height="510" alt="image" src="https://github.com/user-attachments/assets/320bfa31-5982-4ba0-aabf-ccc3ee5811e9" />

# Question 3
**The IT administrator observed multiple MoveToDeletedItems events for the user. How many emails were permanently deleted by the threat actor**

By permanently deleted, we know that it's referring to `HardDeleted` items. Filtering by that Operation for the user `owen.k@tenxfintech.com` we are able to know the total amount of permanently deleted emails.

<img width="1047" height="442" alt="image" src="https://github.com/user-attachments/assets/ea4f4f37-8fc4-4973-a04a-d18348eb1673" />

# Question 4
**What application was used by the attacker to read the emails?**

Looking at the `Consent to Application.` events of the user `owen.k@tenxfintech.com`, and extracting the corresponding `ModifiedProperties` (that contains mainly app permissions/scope given to the tenant, values extracted - shown in `ConsentType` and `Scope` columns) and `ExtendedProperties` (that contains information about the application that was given the permissions by the user - shown in column `OauthAppId`). We can observe that the `AppId` value corresponds to the _eM Client_ app, according to [Huntress](https://huntresslabs.github.io/rogueapps/#:~:text=A%20robust%20email,financial%20transaction%20fraud.), it is "A robust email client often leveraged by attackers due to its extensive capabilities. eM Client allows attackers to sync multiple inboxes into the same client, download all emails from an inbox, mass mail spam, export calendars and contacts, and create inbox rules to stage financial transaction fraud.". \
Additionally, we can observe that the `EWS.AccessAsUser.All` permission can allows the app to have access to all mailboxes in the tenant, which can also be noticed in the `AllPrincipals` value within the `ConsentType` column.

Note: ChatGPT was leveraged to quickly create regex to get the different fields retrived here
<img width="2239" height="1121" alt="image" src="https://github.com/user-attachments/assets/9a2979e9-5db2-461d-a217-6c32c204beaf" />

# Question 5
**The threat actor used the application eM Client to access emails, how many events were generated because of this activity?**

Every `MailItemAccessed` log contains the information of the client that accessed the email/s in the field `ClientAppId`. Having knowledge of which is the AppId of the _em Client_ app, we can filter for only the emails that contain that value in the `ClientAppId` field.

<img width="859" height="439" alt="image" src="https://github.com/user-attachments/assets/e261cc0b-6de5-47b8-9238-1db2ade7614a" />

# Question 6
**The threat actor removed security alerts from the inbox of Owen. What is the subject of one of the emails that was generated in relation to eDiscovery abuse?**

As we don't know which type of deletion was leverage by the threat actor, we are going leave the search open by not specifying a `Operation` value. Then, we will extract the subject for each event and look for any that contains the word "eDiscovery".
<img width="2209" height="557" alt="image" src="https://github.com/user-attachments/assets/43a03abc-1836-4e62-90a7-aa7a9011f517" />

# Question 7
**The threat actor started a search looking for credentials. What is the full search query used?**

As I have never worked with the _eDiscovery_ ("_Discovery_" in UAL), I got myself a bit familiarized with it using the [Audit Log Activities](https://learn.microsoft.com/en-us/purview/audit-log-activities) documentation from MS Learn.

Looking at the operations that could be related to searches, we are likely looking for any of the following, where they all starts with "PurviewSearch" 
<img width="956" height="851" alt="image" src="https://github.com/user-attachments/assets/a8f183af-dc54-4a49-bed2-deb7cb71b90d" />

Looking at the fields we can observe that there is one that contains the query text.
<img width="840" height="744" alt="image" src="https://github.com/user-attachments/assets/49c36564-da29-4e81-9cfb-866ab13a2f64" />

Removing empty values, we can get the search query used.
<img width="594" height="785" alt="image" src="https://github.com/user-attachments/assets/86385a96-c8fd-474d-85fc-e285ab7bdd8a" />

# Question 8
**The threat actor was removed before they could download the eDiscovery results. However, it's still necessary to determine how Owen Kelly's account was initially compromised. 
Owen Kelly remembers receiving an email from a colleague in relationship to DocuSign, but he remembers the link not working and the colleague who allegedly sent it claims they never sent it. Who is the user that sent the phishing email to Owen Kelly?**


