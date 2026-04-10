---
title: Infinity Learning Labs: Storage Container Intrusion Analysis
date: 2026-04-09
---
# Scenario
---
You are tasked with investigating security risks in Secure Corp’s Azure environment, focusing on misconfigured service principals. Recent audits identified that several service principals have overly broad permissions, posing a potential threat for privilege escalation and unauthorized access to sensitive resources.

The first thing I'm doing is familiarizing myself with the data. I've never truly deep dived into data from Azure RBAC. within Activity Logs, so I want to get familiarized with it.

I just started into googling those logs, and the AI summary revealed that it is part of the `AzureActivity` table which from my built knowledge, I know it refers to the `Azure Activity Log` events.
![[Pasted image 20260409173423.png]]

Since part of work responsibilities through the years was working in incidents, I have had the need before to dig into Microsoft logs, and often I reference the multiple audit log schema reference sites that MSFT has for different type of events. Here are a few of sites I've used before to know greater detail about their logs in case that you haven't checked them out: [Audit log activities](https://learn.microsoft.com/en-us/purview/audit-log-activities), [Detailed activity properties in the audit log](https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties), [Office 365 Management Activity API schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema), [Learn about the monitoring and health activity log schemas - Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas).

Naturally, I went into searching for the `Azure Audit Log` event schema to understand better what logs I am looking at.
![[Pasted image 20260409174303.png]]

After going through this it kind of gives me a sense of not being that lost as it lists all the fields available on each of the categories found.

Going back into Elastic, I want to know what data sources I am working on. By googling, it seems that the `event.dataset` field. After looking at it, we can notice there's three data sources:

1. Azure Activity Logs
2. Azure Platform Logs (which after googling they are -> "Azure Monitor Logs")
3. Azure Sign In Logs (Entra Sign In Logs)

![[Pasted image 20260409174737.png]]

Another field that could be of use would be the `event.action` field, that lists several activities involved with storage events mainly...
![[Pasted image 20260409175153.png]]

---
# Question 1
Identify and determine the ip addresses associated with the brute forcing activity.
R= **36.255.87.7 , 36.255.87.5**

Checking on the `azure.platformlogs` (Azure Monitor) Sign In Logs, I discarded this option as there was only 8 events all successful, which is not an indicator of a bruteforce attack.
![[Pasted image 20260409182449.png]]

Checking into the logs with the most amount of entries (`GetBlob` event action), we can observe that there seems to be attempts of reading a blob, with no authentication provided (`azure.activitylogs.identity.type` == `Anonymous`) which failed ("Conflict (HTTP Status Code: 409)" according to [Azure Activity Log event schema](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-schema) ).
![[Pasted image 20260409185048.png]]

Another data point is that this attempt comes from India, which along with the fact that it's attempting to read a blob using Anonymous access (and failed) it is worth it to list the multiple values seen in these fields to know with how many different values are we dealing with (thus proving [or not] a brute force attack.)
![[Pasted image 20260409185621.png]]

With the following search we are able to prove that `36.255.87.7` and `36.255.87.5` were doing brute force attempts against blob resources.

```
FROM az-storage-01
  | WHERE `event.dataset` == "azure.activitylogs" AND `event.action` == "GetBlob"
  | STATS COUNT(), VALUES(azure.activitylogs.category), VALUES(azure.activitylogs.identity.type), VALUES(azure.activitylogs.operation_name), VALUES(azure.activitylogs.statusCode), VALUES(azure.activitylogs.statusText), VALUES(azure.activitylogs.uri), VALUES(azure.resource.id), VALUES(geo.city_name), VALUES(geo.country_iso_code), VALUES(source.as.organization.name) BY source.ip
```

![[Pasted image 20260409190358.png]]

# Question 2
Identify and determine the userAgentHeader associated with the brute forcing activity.
R=**Wfuzz/3.1.0**

We can observe that there's a "wfuzz" reference in the user agent, already knowing that "fuzzing" is an automated process that inputs data to systems to identify bugs, vulnerabilities, etc; this is the brute force activity we are looking for.
![[Pasted image 20260409191725.png]]
