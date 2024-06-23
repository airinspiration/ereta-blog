---
title: "Jinkles"
date: 2024-06-23
---
![image](https://github.com/airinspiration/ereta-blog/assets/99099600/94612a53-48bf-412d-844f-db9f7198c079)

# Scenario
You’re a third-party IR consultant and your manager has just forwarded you a case from a small-sized startup named cloud-guru-management ltd. They’re currently building out a product with their team of developers, but the CEO has received word of mouth communications that their Intellectual Property has been stolen and is in use elsewhere. The user in question says she may have accidentally shared her Documents folder and they have stated they think the attack happened on the 6th of October. The user also states she was away from her computer on this day. There is not a great deal more information from the company besides this. An investigation was initiated into the root cause of this potential theft from Cloud-guru; however, the team has failed to discover the cause of the leak. They have gathered some preliminary evidence for you to go via a KAPE triage. It’s up to you to discover the story of how this all came to be. Warning: This sherlock requires an element of OSINT and players will need to interact with 3rd party services on internet.


### Task 1
Which folders were shared on the host? (Please give your answer comma separated, like this: c:\program files\share1, D:\folder\share2) \
**R= C:\Users\Velma\Documents, C:\Users**

Using some google-fu on anything related to shared folders, I encountered [this](https://medium.com/@boutnaru/the-windows-forensic-journey-shared-folders-windows-shares-f09285287c89) blog, where it states the following:

> ... the name and the folder’s path (shared by the network share) are also stored in the registry as part of the” LanmanServer” service (aka “Server” service) configuration. The full location is “HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Shares” ...

Using the Registry Explorer tool by Eric Zimmerman, I went straight into that location, where I was able to confirm that the shared folders path was shown.

![image](https://github.com/airinspiration/ereta-blog/assets/99099600/e2f225b6-b7d6-4843-94ed-d814d32048bf)

### Task 2
What was the file that gave the attacker access to the users account? \
**R=bk_db.idb**

After a while of going through most of the files, I encountered a .ibd file, which was allocated in the `\Users\Velma\Documents\Python Scripts + things\web server project\testing\logon website\bk` folder. for me `bk_db` means "database backup". Following a research on `.idb` files (InnoDB), seems that MySQL databases can store information in them, thus, access to the stored user credentials in the database.

![image](https://github.com/airinspiration/ereta-blog/assets/99099600/04569232-036d-4669-81f4-96d678cd00b1)


