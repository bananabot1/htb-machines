
| Property         | Value                         |
| ---------------- | ----------------------------- |
| **OS**           | Linux / Windows               |
| **Difficulty**   | Easy / Medium / Hard / Insane |
| **Release Date** | YYYY-MM-DD                    |
| **State**        | YYYY-MM-DD                    |
| **IP**           | 10.10.10.X                    |
| **Techniques**   | technique-1, technique-2      |
| **Tags**         | #web #privesc #linux          |

---
## Summary

Brief 2-3 sentence ogverview of the machine and attack path.

---
## Enumeration

```
 echo '10.129.35.17 orion.htb' | sudo tee -a /etc/hosts
```

Added the ip address of the machine to the /etc/hosts file.
### Nmap Scan

```
 sudo nmap -sCV orion.htb                              
Starting Nmap 7.95 ( https://nmap.org ) at 2026-06-27 06:51 EDT
Nmap scan report for orion.htb (10.129.35.17)
Host is up (0.034s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Orion Telecom
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.12 seconds                                                                              
```

### Service Enumeration

![](./screens/1.png)

Exposed admin endpoint:

```
 gobuster dir -u http://orion.htb -w /home/kali/SecLists/Discovery/Web-Content/raft-large-directories.txt
===============================================================
Gobuster v3.8
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://orion.htb
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /home/kali/SecLists/Discovery/Web-Content/raft-large-directories.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.8
[+] Timeout:                 10s
===============================================================
Starting gobuster in directory enumeration mode
===============================================================
/admin                (Status: 302) [Size: 0] [--> http://orion.htb/admin/login]
/wp-admin             (Status: 418) [Size: 54217]
/logout               (Status: 302) [Size: 0] [--> http://orion.htb/]
/assets               (Status: 301) [Size: 178] [--> http://orion.htb/assets/]
/index                (Status: 200) [Size: 12272]
/p1                   (Status: 200) [Size: 12272]
/p15                  (Status: 200) [Size: 12272]
/p13                  (Status: 200) [Size: 12272]
/p2                   (Status: 200) [Size: 12272]
/p10                  (Status: 200) [Size: 12272]
Progress: 8069 / 62281 (12.96%)^C
```

**Vulnerable Craft CMS 5.6.16:**
![](./screens/2.png)

---
## Foothold

### CVE-2025-32432

Craft is a flexible, user-friendly CMS for creating custom digital experiences on the web and beyond. Starting from version 3.0.0-RC1 to before 3.9.15, 4.0.0-RC1 to before 4.14.15, and 5.0.0-RC1 to before 5.6.17, Craft is vulnerable to unauthenticated remote code execution. Attackers can inject custom PHP objects via the asset generation endpoints to execute arbitrary commands. This is a high-impact, low-complexity attack vector. This issue has been patched in versions 3.9.15, 4.14.15, and 5.6.17, and is an additional fix for CVE-2023-41892. 

The vulnerability works and is exploited in the wild over vulnerable Craft CMS instances if a threat actor  follows: 

- Sending a crafted GET request to _**/index.php?p=admin/dashboard**_ to retrieve a CSRF token from the CraftCMS admin dashboard. 

- Sends a POST request to _**/index.php?p=admin/actions/assets/generate-transform**_ with a specially crafted JSON payload and retrieves a valid asset ID through PHP object injection. 

- The payload includes a PHP object that gets deserialized, leading to arbitrary code execution through the _**GuzzleHttp\Psr7\FnStream**_ class.

### Exploitation

PoC

```shell
# Commands used
```

---
## User Flag

### Lateral Movement (if applicable)

Steps to move from initial foothold to user access.

---
## Privilege Escalation

### Enumeration

What you found that leads to root/admin.

### Exploitation

Step-by-step privilege escalation.

```shell
# Commands used
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