---
title: "Silent Forwarding: Detecting Malicious Mailbox Rules"
date: 2026-04-18
---

# Background
Threat actors often exploit mailbox rules to silently manipulate email flow, deleting security alerts, hiding legitimate messages, or forwarding sensitive content externally. You'll act as a security analyst investigating suspicious mailbox rule activity within a Microsoft 365 environment.

# Objectives
1. Identify malicious mailbox rules that could allow threat actors to maintain persistence
2. Detect email forwarding that could lead to data exfiltration
3. Analyze suspicious rules designed to hide specific email content

# Question 1
How many users have mailbox rules?

The data provided was collected using the module `Get-MailboxRules` from `Microsoft-Extractor-Suite`, which contains mailbox rule configuration activity. Knowing that we have the information from mailbox rules from users, we just get all the different values from the user field.
<img width="1033" height="673" alt="image" src="https://github.com/user-attachments/assets/5242ca5e-43ee-404f-b97b-6c1e64e840ed" />
