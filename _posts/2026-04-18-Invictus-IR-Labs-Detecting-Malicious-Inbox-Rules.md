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
**How many users have mailbox rules?** \
The data provided was collected using the module `Get-MailboxRules` from `Microsoft-Extractor-Suite`, which contains mailbox rule configuration activity. Knowing that we have the information from mailbox rules from users, we just get all the different values from the user field.
![image](https://github.com/user-attachments/assets/5242ca5e-43ee-404f-b97b-6c1e64e840ed)

# Question 2
**Which user has the most mailbox rules?** \
By counting the number of times a user appears and then sorting it from most repeated to less, we are able to know which user has the most amount of mailbox rules.
![image](https://github.com/user-attachments/assets/d8a00468-871d-4dee-a6d7-9e6e4c8df770)

# Question 3
**A common tactic used by threat actors is to move emails containing specific keywords to a hidden or less-noticed folder. Can you identify the name of the malicious rule that performs this action?** \

Looking at the fields of the logs provided, three fields could be of use to answer this question: `SubjectContainsWords`, `SubjectOrBodyContainsWords` and `BodyContainsWords`. Lets get all the different values from it to see if I can find any value of interest.
![image](https://github.com/user-attachments/assets/60c11be3-abda-4898-a0db-4a1c2b07de16)

Scrolling through the values, we can observe that there is only rule which as set the condition to move emails if `phishing, attack, compromise, hack, BEC, malicious` appear in the subject or body. 
![image](https://github.com/user-attachments/assets/40753112-1d3b-4223-9489-8c1158b5a56f)

Checking at that entry, notice that the `RuleName` is also particularly strange, as it's only a _dot_, which is common to see in mailbox rules crated by threat actors as an attempt to make it camouflage with the other rules. Also notice that the `MoveToFolder` action is set to move it to the `Archive` folder, which users rarely check on it.
![image](https://github.com/user-attachments/assets/e94cd7ce-f258-4eae-9835-b0e4ca2e8575)

# Question 4
**How many keywords in the subject or body does this rule trigger on?** 

From the previous question, we know that the rule moves emails that contain `phishing, attack, compromise, hack, BEC, malicious` to the `Archive Folder` if they are within the subject or body.

# Question 5
**Another tactic used by threat actors is to use short names or names containing non-alphanumeric characters. In the previous question, you identified a rule with a short name. What is the name of another rule that contains non-alphanumeric characters?**

With the help of ChatGPT, I was able to get get a regex to look for non-alphanumeric values within the `RuleName`, which states that the entire value should contain any values from `a-z`,`A-Z`, `0-9`. Which in this case we can observe the other strange rule.
![image](https://github.com/user-attachments/assets/20b0ecdb-b3d7-44be-9c45-f5d08be2670b)

# Question 6
**The rule identified in the previous questions deletes emails received from a specific sender. What is the sender's email address?** \

From the previous question we know that the name of the rule mentioned in the previous question is `发`, searching for `RuleName` that contains that value and displaying the `From` column value through the `project` command.
![image](https://github.com/user-attachments/assets/37cf5381-366f-4a3e-9fd7-5db794bdf455)

# Question 7
**Another malicious rule is forwarding emails that match at least 4 keywords to an external email address. What is the email address receiving the forwarded emails?**

First I made sure that we only are working with the entries that do contain a value in `ForwardTo` and also that the address is not an internal email address, as the intention of the attacker is to have the contents of the emails on his complete control without the possibility of being impeded from keeping control of an email account.
In question 3 we learned that conditions to forward, move or do any action are set on the fields `SubjectContainsWords`, `SubjectOrBodyContainsWords` and `BodyContainsWords`. Knowing this, we checked for the length (leveraging `array_length()`) of each of these fields that have been splitted by the `split()` command, using `,` as separator as we know that each value is separated by it.
![image](https://github.com/user-attachments/assets/98c2ee98-0bf8-4ab1-aabe-ba4df6a56c51)

# Question 8
**Threat actors can be a bit more sneaky, it's possible to add multiple email addresses in a forwarding rule. What is the external email address where this trick was used?**

The `ForwardTo` field shows internal exchange references for internal addresses that start with `EX:` and SMTP references for external addresses that start with `SMTP:` when filtering by these we can found the other address to which is forwarding the emails to.
![image](https://github.com/user-attachments/assets/2f752e14-87c9-46b2-a60c-c92ccb803627)

