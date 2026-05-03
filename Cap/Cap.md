
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

---
## Foothold

How you gained initial access to the machine.

### Vulnerability

Description of the vulnerability exploited.

### Exploitation

Step-by-step exploitation with commands.

```shell
# Commands used
```

---
## User Flag

### Lateral Movement (if applicable)

Steps to move from initial foothold to user access.

### Flag

```
user.txt: ********************************
```

---
## Privilege Escalation

### Enumeration

What you found that leads to root/admin.

### Exploitation

Step-by-step privilege escalation.

```shell
# Commands used
```

### Root Flag

```
root.txt: ********************************
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