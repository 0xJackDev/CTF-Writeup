### GreenHorn CTF Walkthrough by Jack Buchanan

This is a detailed walkthrough on how I tackled the GreenHorn box. The write-up is divided into three main sections: Enumeration, Exploit, and Privilege Escalation.

---

#### **Enumeration**

The first step is to identify the available services and ports on the target machine. I began by running an Nmap scan.

bash



`skid@skidlord:~/Downloads$ nmap -sC -sV 10.10.11.25`

**Nmap Results:**



Copy code

`22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0) 80/tcp   open  http    nginx 1.18.0 (Ubuntu) 3000/tcp open  ppp?    Gitea`

The scan revealed three open ports:

- **Port 22 (SSH)** - Running OpenSSH 8.9p1
- **Port 80 (HTTP)** - Running Nginx 1.18.0
- **Port 3000 (Gitea)** - Gitea is a Git self-hosting service.

I found two web servers:

- **Webserver 1** on port 80, which redirects to `http://greenhorn.htb/`.
- **Webserver 2** on port 3000, running Gitea, which hosts the source code for webserver 1.

---

##### **Vulnerability Discovery**

I discovered that the Gitea version was **1.21.11**, which is vulnerable to a **Stored XSS attack** (CVE-2024-6886). I referred to the [exploit details here](https://sploitus.com/exploit?id=PACKETSTORM:180457).

To reproduce the vulnerability:

1. Register an account and log in on Gitea.
2. Navigate to the repository settings and insert the following payload into the **Description** field:
    
    html
    
    Copy code
    
    `<a href=javascript:alert()>XSS test</a>`
    
3. The payload triggers XSS when visiting the repository page.

After experimenting, I realized **Gitea 1.21.11** was not vulnerable to this issue, so I shifted focus to the available files.

##### **Source Code Review**

Upon reviewing the source code hosted on Gitea, I discovered a link to `pass.php`:

php

Copy code

`require_once 'data/settings/pass.php';`

This file contained a hashed password:

Copy code

`d5443aef1b64544f3685bf112f6c405218c573c7279a831b1fe9612e3a4d770486743c5580556c0d838b51749de15530f87fb793afdcc689b6b39024d7790163`

After cracking the hash, the password was revealed but i wont put this here since its still an active box.

##### **Gaining Access**

I used this password to log into **Webserver 1** on port 80, which only required a password (no username). Upon logging in, I discovered that the web application was running **Pluck CMS v4.7.18**.

Pluck CMS 4.7.18 is vulnerable to **CVE-2023-50564**, allowing unauthorized file uploads. I used a PoC found [here](https://github.com/Rai2en/CVE-2023-50564_Pluck-v4.7.18_PoC).

**Steps to exploit:**

1. Modify the PoC to fit the GreenHorn setup (e.g., updating the target URL and removing the username field).
2. Upload a PHP reverse shell using the PoC.

After uploading the shell, I accessed it and got a reverse shell on the server. and got the user flag.

---

#### **Privilege Escalation**

Once inside the box, I noticed a file named `Using OpenVAS.pdf` in the home directory. To retrieve this file, I set up a simple HTTP server on my machine and used **wget** to download the file from the target:

bash

Copy code

`python3 -m http.server 8080 wget http://10.10.11.25:8080/'Using OpenVAS.pdf'`

##### **Extracting the Password**

The PDF contained a pixelated password. I used **Depix**, a tool that reconstructs pixelated text, to reveal the password.

1. I extracted the image from the PDF using `pdfimages`.
2. Then, I used **Depix** to recover the password.

After obtaining the password, I used it to switch to the **junior** user account and eventually to root.

##### **Root Access**

I used the root password to SSH into the box:

bash

Copy code

`ssh root@10.10.11.25`

Finally, I accessed the root flag.

---

### Conclusion:

This was an exciting box with several challenges. The main takeaways were:

- Discovering the source code in Gitea.
- Cracking the password hash to gain initial access.
- Exploiting a CVE to upload a zip file containing a malicious reverse shell to get a foothold
- Using a pixelated password extraction tool (Depix) to reveal the root password.

This box demonstrates the importance of inspecting source code and using automation for vulnerabilities like file uploads and pixelated data recovery.