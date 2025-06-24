---
title: "Smishing - Information Stealer"
date: 2025-06-24
---

Today, I've just received the following instant message. The translated message is as follows: 
> We weren't able to setup your package deliver because the address that you provided doesn't
match with the postal code, update in: `https[://]estafetaems[.]top/mc`.

![image](https://github.com/user-attachments/assets/ff4cb156-ebb4-45f6-8c18-0d3b1b644873)

It's clearly this is one of those mass sent smishing, but what is the purpose of these? Let's explore...

Checking the WHOIS record, there are two red flags about this domain:

1. The domain was bought from those websites that sell low-cost domains.
![image](https://github.com/user-attachments/assets/6d235240-cf34-4f05-90fa-bacb5ad7fda9)

2. The domain was just bought a day ago (at the time of this writing), which no legit domain is usually this young.

![image](https://github.com/user-attachments/assets/59962abf-2092-4a3a-bc25-659069780579)

Leveraging tria.ge to explore the site, at first glance, we can see that it attempts to impersonate the estafeta site, even though it seems like an older version of the current one, 
as we can observe the clear differences with the second screenshot which is the current website.
![image](https://github.com/user-attachments/assets/959616e3-8782-425d-976d-9677c9ecc3f8)

![image](https://github.com/user-attachments/assets/b5d4b890-6f16-4094-92b8-6546f98b46ad)

Checking at the resources contained in the website, we have proof that this site was cloned towards the end of the year 2023 (likely December).
![image](https://github.com/user-attachments/assets/99e41ead-9c1d-4318-b741-b4fe17be4588)

![image](https://github.com/user-attachments/assets/878b8ea0-4270-4be0-a621-d615c926ec7b)

Checking the `.js` file, we can observe that there are some comments in chinese, which means one of two things: the threat actors are chinese/familiarized with chinese or whatever code they copied this from
was written by chinese/familized with chinese.
![image](https://github.com/user-attachments/assets/fcb2c9c2-7f7d-43be-8dc9-c8439521d65e)

As soon as the user stops writing, the data is sent to the endpoint `/api/input`, along with the timestamp in epoch.
![image](https://github.com/user-attachments/assets/a24ef0fe-b25a-486e-b2f1-2ca4eb9bad36)

![image](https://github.com/user-attachments/assets/344644b8-899d-41da-bc51-e49a7a7eab7b)

The server then replies with a `code: 0`.
![image](https://github.com/user-attachments/assets/8375ea97-6f65-4be4-af1e-05a660a60e30)

Within the request, there's interesting information that gives us more information on the threat actor infrastructure:
1. The `Server` field is `GoFrame HTTP Server`. When googling it, we can see that the first result is in Chinese, within that website there's a QR code so that we can follow the project in `WeChat`, which is a social media
platoform only used in China. If we piece together the two evidences that we have until now (comments written in Chinese and the use of an opensource web server that prompts the users to follow them using `WeChat`), we can confidently
state that the attacker/s is from China.
![image](https://github.com/user-attachments/assets/7f9f8f61-ba45-491f-a021-772be61ad76f)

2. There's a `Via` field with the value of `1.1 Caddy`. I've found in Google that Caddy is a:
> Caddy sports a flexible and powerful HTTP reverse proxy, on-line configuration API, and a robust, production-ready static file server, and serves all sites over HTTPS by default with automagic TLS certificates.

3. The field `Sec-Ch-Ua-Platform` with the value of `Windows`, let us know that it is able to automatically identify the platform connecting to the site.
4. There's a `Token` field, which is unknown at the time what's its purpose.
![image](https://github.com/user-attachments/assets/be28d121-00f3-4776-b864-c2fd449a6c14)

Once we hit `Submit`, we are then prompted to insert our credit card information.
![image](https://github.com/user-attachments/assets/af5228e0-9c38-4603-9a8c-c05866deeb4f)

Once we entered the information (and it was being sent at the same time it was being written), once we submitted it, a secure web socket (`wss://`) request was sent to the endpoint `/ws` with the previously seen token being passed as argument.
![image](https://github.com/user-attachments/assets/d7b5e4ef-c96a-4bdd-86c8-469b6c72fc74)

Within that same request, in the `result_type` event, we are able to observe the data that was transmitted to the server, the app is able to determine whether or not if the card number is a valid one or not from the first digits (as in
another attempt I invented all the names, in this case I put only the initial real numbers from an HSBC card).
![image](https://github.com/user-attachments/assets/f17b8088-5d88-4048-a664-efe714618441)

When you submit the info, at the end it redirects you to the legit `estafeta.com` website


