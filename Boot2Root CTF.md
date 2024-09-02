

Hi my name is Jack Buchanan this is my write up for the Easy Boot2Root Box on TryHackMe


Machine IP: 10.10.139.187

skid@skidlord:~/pen$ nmap -sC -sV 10.10.139.187
Starting Nmap 7.93 ( https://nmap.org ) at 2024-09-02 15:32 EDT                             
Nmap scan report for 10.10.139.187                                                          
Host is up (0.20s latency).                                                                 
Not shown: 998 closed tcp ports (conn-refused)                                              
PORT   STATE SERVICE VERSION                                                                
21/tcp open  ftp     vsftpd 3.0.3                                                           
| ftp-anon: Anonymous FTP login allowed (FTP code 230)                                      
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 bin                               
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 boot                              
| drwxr-xr-x   17 0        0            3700 Sep 02 12:29 dev                               
| drwxr-xr-x   85 0        0            4096 Aug 13  2019 etc                               
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 home                              
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img -> boot/initrd.img-4.4.0-157-generic                                                                               
| lrwxrwxrwx    1 0        0              33 Aug 11  2019 initrd.img.old -> boot/initrd.img-4.4.0-142-generic                                                                           
| drwxr-xr-x   19 0        0            4096 Aug 11  2019 lib                               
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 lib64                             
| drwx------    2 0        0           16384 Aug 11  2019 lost+found                        
| drwxr-xr-x    4 0        0            4096 Aug 11  2019 media
| drwxr-xr-x    2 0        0            4096 Feb 26  2019 mnt
| drwxrwxrwx    2 1000     1000         4096 Aug 11  2019 notread [NSE: writeable]
| drwxr-xr-x    2 0        0            4096 Aug 11  2019 opt
| dr-xr-xr-x   96 0        0               0 Sep 02 12:29 proc
| drwx------    3 0        0            4096 Aug 11  2019 root
| drwxr-xr-x   18 0        0             540 Sep 02 12:29 run
| drwxr-xr-x    2 0        0           12288 Aug 11  2019 sbin
| drwxr-xr-x    3 0        0            4096 Aug 11  2019 srv
| dr-xr-xr-x   13 0        0               0 Sep 02 12:29 sys
|_Only 20 shown. Use --script-args ftp-anon.maxlist=-1 to see all.
| ftp-syst: 
|   STAT: 
| FTP server status:
|      Connected to ::ffff:10.13.66.27
|      Logged in as ftp
|      TYPE: ASCII
|      No session bandwidth limit
|      Session timeout in seconds is 300
|      Control connection is plain text
|      Data connections will be plain text
|      At session startup, client count was 2
|      vsFTPd 3.0.3 - secure, fast, stable
|_End of status
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 8af9483e11a1aafcb78671d02af624e7 (RSA)
|   256 735dde9a886e647ae187ec65ae1193e3 (ECDSA)
|_  256 56f99f24f152fc16b77ba3e24f17b4ea (ED25519)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel



From this nmap scan i see that there is two common ports open. Ftp and SSH 

First Im gonna look into the ftp server since it allows anonymous logins. 

inside of the home directory i see a directory called melodias I will assume this a user and will be helpful if i need to brute force ssh.


well inside of that i actually found the user flag. Which was really really really easy.

After looking around i found a intresting directory named noread 

-rwxrwxrwx    1 1000     1000          524 Aug 11  2019 backup.pgp
-rwxrwxrwx    1 1000     1000         3762 Aug 11  2019 private.asc
which had these two files. I downloaded them and the private.asc was a pgp private key


this private.asc key was behind a passphrase so i used the gpg2john tool to turn it into a hash and cracked it with the rockyou wordlist and found the password is xbox360. Now i can decrypt the backup.pgp message which was a /etc/shadow file which includes the root hash 
root:$6$07nYFaYf$F4VMaegmz7dKjsTukBLh6cP01iMmL7CiQDt1ycIm6a.bsOIBp0DwXVb9XI2EtULXJzBtaMZMNd2tV4uob5RVM0:18120:0:99999:7:::
![[Screenshot from 2024-09-02 16-23-54.png]]


so this is an easy one i just crack the root hash using the rockyou wordlist and boom i should just be able to ssh in as root


and boom cracked in less then 5 seconds
![[Screenshot from 2024-09-02 16-25-19.png]]

so i just ssh into root with the info and

![[Screenshot from 2024-09-02 16-28-15.png]]


This is probably one of the easiest boxes ive ever done. Only hard part is that TryHackMe's servers are just very unreliable. Thank you for your time.