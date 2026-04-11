---
title: Infinity Learning Labs - Storage Container Intrusion Analysis
date: 2026-04-09
---
# Scenario
---
You are tasked with investigating security risks in Secure Corp’s Azure environment, focusing on misconfigured service principals. Recent audits identified that several service principals have overly broad permissions, posing a potential threat for privilege escalation and unauthorized access to sensitive resources.

---
The first thing I'm doing is familiarizing myself with the data. I've never truly deep dived into data from Azure RBAC. within Activity Logs, so I want to get familiarized with it.2

I just started into googling those logs, and the AI summary revealed that it is part of the `AzureActivity` table which from my built knowledge, I know it refers to the `Azure Activity Log` events.

![image](https://github.com/user-attachments/assets/15ca8a49-f5e6-4c48-b007-a72ffb1e3cc6)


Since part of work responsibilities through the years was working in incidents, I have had the need before to dig into Microsoft logs, and often I reference the multiple audit log schema reference sites that MSFT has for different type of events. Here are a few of sites I've used before to know greater detail about their logs in case that you haven't checked them out: [Audit log activities](https://learn.microsoft.com/en-us/purview/audit-log-activities), [Detailed activity properties in the audit log](https://learn.microsoft.com/en-us/purview/audit-log-detailed-properties), [Office 365 Management Activity API schema](https://learn.microsoft.com/en-us/office/office-365-management-api/office-365-management-activity-api-schema), [Learn about the monitoring and health activity log schemas - Microsoft Entra ID](https://learn.microsoft.com/en-us/entra/identity/monitoring-health/concept-activity-log-schemas).

Naturally, I went into searching for the `Azure Audit Log` event schema to understand better what logs I am looking at.
![image](https://github.com/user-attachments/assets/b99541ae-e709-46b6-bfbb-aad2b19ca053)


After going through this it kind of gives me a sense of not being that lost as it lists all the fields available on each of the categories found.

Going back into Elastic, I want to know what data sources I am working on. By googling, it seems that the `event.dataset` field. After looking at it, we can notice there's three data sources:

1. Azure Activity Logs
2. Azure Platform Logs (which after googling they are -> "Azure Monitor Logs")
3. Azure Sign In Logs (Entra Sign In Logs)

![image](https://github.com/user-attachments/assets/7561fc8f-0623-4200-8e7d-62997c9f40bc)

Another field that could be of use would be the `event.action` field, that lists several activities involved with storage events mainly...
![image](https://github.com/user-attachments/assets/c1e92174-365a-4f05-af4a-20e6274852eb)

---
# Question 1
Identify and determine the ip addresses associated with the brute forcing activity. \
R= **36.255.87.7 , 36.255.87.5**

Checking on the `azure.platformlogs` (Azure Monitor) Sign In Logs, I discarded this option as there was only 8 events all successful, which is not an indicator of a bruteforce attack.
![image](https://github.com/user-attachments/assets/0b11de02-4e11-4db2-a247-a06ded27c235)

Checking into the logs with the most amount of entries (`GetBlob` event action), we can observe that there seems to be attempts of reading a blob, with no authentication provided (`azure.activitylogs.identity.type` == `Anonymous`) which failed ("Conflict (HTTP Status Code: 409)" according to [Azure Activity Log event schema](https://learn.microsoft.com/en-us/azure/azure-monitor/platform/activity-log-schema) ).
![image](https://github.com/user-attachments/assets/bceea038-693f-4ebf-850b-72dada7396b7)

Another data point is that this attempt comes from India, which along with the fact that it's attempting to read a blob using Anonymous access (and failed) it is worth it to list the multiple values seen in these fields to know with how many different values are we dealing with (thus proving [or not] a brute force attack.)

![image](https://github.com/user-attachments/assets/cdb0781a-2f10-4124-8edf-f91edcf6eb57)

With the following search we are able to prove that `36.255.87.7` and `36.255.87.5` were doing brute force attempts against blob resources.

```kql
FROM az-storage-01
  | WHERE `event.dataset` == "azure.activitylogs" AND `event.action` == "GetBlob"
  | STATS COUNT(), VALUES(azure.activitylogs.category), VALUES(azure.activitylogs.identity.type), VALUES(azure.activitylogs.operation_name), VALUES(azure.activitylogs.statusCode), VALUES(azure.activitylogs.statusText), VALUES(azure.activitylogs.uri), VALUES(azure.resource.id), VALUES(geo.city_name), VALUES(geo.country_iso_code), VALUES(source.as.organization.name) BY source.ip
```

![image](https://github.com/user-attachments/assets/df63c5da-547f-4751-82f6-be79b28fbfac)

# Question 2
Identify and determine the userAgentHeader associated with the brute forcing activity. \
R=**Wfuzz/3.1.0**

We can observe that there's a "wfuzz" reference in the user agent, already knowing that "fuzzing" is an automated process that inputs data to systems to identify bugs, vulnerabilities, etc; this is the brute force activity we are looking for.
<img width="594" height="1180" alt="image" src="https://github.com/user-attachments/assets/f12556bf-e55c-428a-8ae1-c1dd089f2d4b" />
