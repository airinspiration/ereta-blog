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

From the third screenshot in question 1, we know that the `ExchangeItemGroup` record type contains the `MoveToDeletedItems` events. Knowing this fact, we can move further and start looking into the data.

Knowing the IP's from the TA, we filter by them, after that we are left off with all the events registered, but notice in the `AuditData_AffectedItems` field, it is of type array due to the brackets in before the start of the value, so there can be 1 or more items.
<img width="2497" height="1176" alt="image" src="https://github.com/user-attachments/assets/f70d7993-9a6c-4e24-be57-8c92193878a4" />

THIS IS WHERE I GOT TO SO FAR, IT IS INCORRECT
UnifiedAuditLog_CL
| where AuditLogRecordType == "ExchangeItemGroup" and Operation == "MoveToDeletedItems"
| extend d = parse_json(AuditData)
| evaluate bag_unpack(d, 'AuditData_')
| where TimeGenerated > ago(30d) 
| where AuditData_ClientIPAddress in ("20.197.88.241", "134.149.200.179")
| extend ItemsDeleted = array_length(todynamic(AuditData_AffectedItems))
| summarize TotalEmailsDeleted = sum(ItemsDeleted)

<img width="993" height="503" alt="image" src="https://github.com/user-attachments/assets/b6c9c357-0198-4a2f-b7d9-a4d3317f4438" />
