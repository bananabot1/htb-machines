
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

### Nmap Scan

```
 nmap -sCV support.htb
Starting Nmap 7.95 ( https://nmap.org ) at 2026-07-06 06:50 EDT
Nmap scan report for support.htb (10.129.230.181)
Host is up (0.11s latency).
Not shown: 988 filtered tcp ports (no-response)
PORT     STATE SERVICE       VERSION
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2026-07-06 10:51:00Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: support.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
5985/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-title: Not Found
|_http-server-header: Microsoft-HTTPAPI/2.0
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2026-07-06T10:51:07
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 65.96 seconds

```

### SMB Enumeration

```
smbclient -L //support.htb -N

        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share 
        support-tools   Disk      support staff tools
        SYSVOL          Disk      Logon server share 
Reconnecting with SMB1 for workgroup listing.
do_connect: Connection to support.htb failed (Error NT_STATUS_RESOURCE_NAME_NOT_FOUND)
Unable to connect with SMB1 -- no workgroup available
                                                                                                                                                                                                                                    
┌──(kali㉿kali)-[~]
└─$ smbclient //support.htb/support-tools -N
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Wed Jul 20 13:01:06 2022
  ..                                  D        0  Sat May 28 07:18:25 2022
  7-ZipPortable_21.07.paf.exe         A  2880728  Sat May 28 07:19:19 2022
  npp.8.4.1.portable.x64.zip          A  5439245  Sat May 28 07:19:55 2022
  putty.exe                           A  1273576  Sat May 28 07:20:06 2022
  SysinternalsSuite.zip               A 48102161  Sat May 28 07:19:31 2022
  UserInfo.exe.zip                    A   277499  Wed Jul 20 13:01:07 2022
  windirstat1_1_2_setup.exe           A    79171  Sat May 28 07:20:17 2022
  WiresharkPortable64_3.6.5.paf.exe      A 44398000  Sat May 28 07:19:43 2022

                4026367 blocks of size 4096. 959242 blocks available
smb: \> get UserInfo.exe.zip
getting file \UserInfo.exe.zip of size 277499 as UserInfo.exe.zip (328.1 KiloBytes/sec) (average 328.1 KiloBytes/sec)
smb: \> 

```

```
ilspycmd UserInfo.exe
using System;
using System.Collections;
using System.Diagnostics;
using System.DirectoryServices;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MatthiWare.CommandLine;
using MatthiWare.CommandLine.Abstractions.Command;
using MatthiWare.CommandLine.Core.Attributes;
using UserInfo.Services;

[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: AssemblyTitle("UserInfo")]
[assembly: AssemblyDescription("")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyProduct("UserInfo")]
[assembly: AssemblyCopyright("Copyright ©  2022")]
[assembly: AssemblyTrademark("")]
[assembly: ComVisible(false)]
[assembly: Guid("5a280d0b-9fd0-4701-8f96-82e2f1ea9dfb")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
[assembly: AssemblyVersion("1.0.0.0")]
namespace UserInfo
{
        internal class Program
        {
                private static async Task Main(string[] args)
                {
                        CommandLineParser<GlobalOptions> commandLineParser = new CommandLineParser<GlobalOptions>(new CommandLineParserOptions
                        {
                                AppName = "UserInfo.exe"
                        });
                        commandLineParser.DiscoverCommands(Assembly.GetExecutingAssembly());
                        _ = (await commandLineParser.ParseAsync(args)).HasErrors;
                }
        }
        public class GetUserOptions
        {
                [Name("username")]
                [Required(true)]
                [Description("Username")]
                public string UserName { get; set; }
        }
        public class FindUserOptions
        {
                [Name("first")]
                [Description("First name")]
                public string FirstName { get; set; }

                [Name("last")]
                [Description("Last name")]
                public string LastName { get; set; }
        }
        public class GlobalOptions
        {
                [Name("v", "verbose")]
                [DefaultValue(false)]
                [Description("Verbose output")]
                public bool Verbose { get; set; }
        }
}
namespace UserInfo.Services
{
        internal class Protected
        {
                private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

                private static byte[] key = Encoding.ASCII.GetBytes("armando");

                public static string getPassword()
                {
                        byte[] array = Convert.FromBase64String(enc_password);
                        byte[] array2 = array;
                        for (int i = 0; i < array.Length; i++)
                        {
                                array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
                        }
                        return Encoding.Default.GetString(array2);
                }
        }
        internal class LdapQuery
        {
                private DirectoryEntry entry;

                private DirectorySearcher ds;

                public LdapQuery()
                {
                        //IL_0018: Unknown result type (might be due to invalid IL or missing references)
                        //IL_0022: Expected O, but got Unknown
                        //IL_0035: Unknown result type (might be due to invalid IL or missing references)
                        //IL_003f: Expected O, but got Unknown
                        string password = Protected.getPassword();
                        entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
                        entry.set_AuthenticationType((AuthenticationTypes)1);
                        ds = new DirectorySearcher(entry);
                }

                public void query(string first, string last, bool verbose = false)
                {
                        //IL_011e: Unknown result type (might be due to invalid IL or missing references)
                        try
                        {
                                if (first == null && last == null)
                                {
                                        Console.WriteLine("[-] At least one of -first or -last is required.");
                                        return;
                                }
                                string text = ((last == null) ? ("(givenName=" + first + ")") : ((first != null) ? ("(&(givenName=" + first + ")(sn=" + last + "))") : ("(sn=" + last + ")")));
                                if (verbose)
                                {
                                        Console.WriteLine("[*] LDAP query to use: " + text);
                                }
                                ds.set_Filter(text);
                                ds.get_PropertiesToLoad().Add("sAMAccountName");
                                SearchResultCollection val = ds.FindAll();
                                if (val.get_Count() == 0)
                                {
                                        Console.WriteLine("[-] No users identified with that query.");
                                        return;
                                }
                                if (verbose)
                                {
                                        string text2 = "[+] Found " + val.get_Count() + " result";
                                        if (val.get_Count() > 1)
                                        {
                                                text2 += "s";
                                        }
                                        text2 += ":";
                                        Console.WriteLine(text2);
                                }
                                foreach (SearchResult item in val)
                                {
                                        if (verbose)
                                        {
                                                Console.Write("       ");
                                        }
                                        Console.WriteLine(item.get_Properties().get_Item("sAMAccountName").get_Item(0));
                                }
                        }
                        catch (Exception ex)
                        {
                                Console.WriteLine("[-] Exception: " + ex.Message);
                        }
                }

                public void printUser(string username, bool verbose = false)
                {
                        try
                        {
                                if (verbose)
                                {
                                        Console.WriteLine("[*] Getting data for " + username);
                                }
                                ds.set_Filter("sAMAccountName=" + username);
                                ds.get_PropertiesToLoad().Add("pwdLastSet");
                                ds.get_PropertiesToLoad().Add("lastLogon");
                                ds.get_PropertiesToLoad().Add("givenName");
                                ds.get_PropertiesToLoad().Add("sn");
                                ds.get_PropertiesToLoad().Add("mail");
                                SearchResult val = ds.FindOne();
                                if (val == null)
                                {
                                        Console.WriteLine("[-] Unable to locate " + username + ". Please try the find command to get the user's username.");
                                        return;
                                }
                                if (((ReadOnlyCollectionBase)(object)val.get_Properties().get_Item("givenName")).Count > 0)
                                {
                                        Console.WriteLine("First Name:           " + val.get_Properties().get_Item("givenName").get_Item(0));
                                }
                                if (((ReadOnlyCollectionBase)(object)val.get_Properties().get_Item("sn")).Count > 0)
                                {
                                        Console.WriteLine("Last Name:            " + val.get_Properties().get_Item("sn").get_Item(0));
                                }
                                if (((ReadOnlyCollectionBase)(object)val.get_Properties().get_Item("mail")).Count > 0)
                                {
                                        Console.WriteLine("Contact:              " + val.get_Properties().get_Item("mail").get_Item(0));
                                }
                                if (val.get_Properties().Contains("pwdLastSet"))
                                {
                                        Console.WriteLine("Last Password Change: " + DateTime.FromFileTime((long)val.get_Properties().get_Item("pwdLastSet").get_Item(0)));
                                }
                        }
                        catch (Exception ex)
                        {
                                Console.WriteLine("[-] Exception: " + ex.Message);
                        }
                }
        }
}
namespace UserInfo.Commands
{
        public class FindUser : Command<GlobalOptions, FindUserOptions>
        {
                public override void OnConfigure(ICommandConfigurationBuilder builder)
                {
                        builder.Name("find").Description("Find a user");
                }

                public override async Task OnExecuteAsync(GlobalOptions options, FindUserOptions commandOptions, CancellationToken cancellationToken)
                {
                        new LdapQuery().query(commandOptions.FirstName, commandOptions.LastName, options.Verbose);
                }
        }
        public class GetUser : Command<GlobalOptions, GetUserOptions>
        {
                public override void OnConfigure(ICommandConfigurationBuilder builder)
                {
                        builder.Name("user").Description("Get information about a user");
                }

                public override async Task OnExecuteAsync(GlobalOptions options, GetUserOptions commandOptions, CancellationToken cancellationToken)
                {
                        new LdapQuery().printUser(commandOptions.UserName, options.Verbose);
                }
        }
}
```

Decrypting the password:

```python
import base64

enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E"
key = b"armando"

data = bytearray(base64.b64decode(enc_password))

for i in range(len(data)):
    data[i] = (data[i] ^ key[i % len(key)]) ^ 0xDF

# Encoding.Default in .NET Framework is typically the system's ANSI codepage
# (often Windows-1252 / cp1252 on US/Western European systems).
# .NET Core/5+ treats Encoding.Default as UTF-8.
try:
    result = data.decode("cp1252")
except UnicodeDecodeError:
    result = data.decode("utf-8", errors="replace")

print(result)

```
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


```

```

```
 
```



Users 

```
dapsearch -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "(objectClass=user)" sAMAccountName | grep "sAMAccountName:"
```

User support: 
```
ldapsearch -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "(sAMAccountName=support)"
```

```
ilspycmd UserInfo.exe
using System;
using System.Collections;
using System.Diagnostics;
using System.DirectoryServices;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using MatthiWare.CommandLine;
using MatthiWare.CommandLine.Abstractions.Command;
using MatthiWare.CommandLine.Core.Attributes;
using UserInfo.Services;

[assembly: CompilationRelaxations(8)]
[assembly: RuntimeCompatibility(WrapNonExceptionThrows = true)]
[assembly: Debuggable(DebuggableAttribute.DebuggingModes.IgnoreSymbolStoreSequencePoints)]
[assembly: AssemblyTitle("UserInfo")]
[assembly: AssemblyDescription("")]
[assembly: AssemblyConfiguration("")]
[assembly: AssemblyCompany("")]
[assembly: AssemblyProduct("UserInfo")]
[assembly: AssemblyCopyright("Copyright ©  2022")]
[assembly: AssemblyTrademark("")]
[assembly: ComVisible(false)]
[assembly: Guid("5a280d0b-9fd0-4701-8f96-82e2f1ea9dfb")]
[assembly: AssemblyFileVersion("1.0.0.0")]
[assembly: TargetFramework(".NETFramework,Version=v4.8", FrameworkDisplayName = ".NET Framework 4.8")]
[assembly: AssemblyVersion("1.0.0.0")]
namespace UserInfo
{
        internal class Program
        {
                private static async Task Main(string[] args)
                {
                        CommandLineParser<GlobalOptions> commandLineParser = new CommandLineParser<GlobalOptions>(new CommandLineParserOptions
                        {
                                AppName = "UserInfo.exe"
                        });
                        commandLineParser.DiscoverCommands(Assembly.GetExecutingAssembly());
                        _ = (await commandLineParser.ParseAsync(args)).HasErrors;
                }
        }
        public class GetUserOptions
        {
                [Name("username")]
                [Required(true)]
                [Description("Username")]
                public string UserName { get; set; }
        }
        public class FindUserOptions
        {
                [Name("first")]
                [Description("First name")]
                public string FirstName { get; set; }

                [Name("last")]
                [Description("Last name")]
                public string LastName { get; set; }
        }
        public class GlobalOptions
        {
                [Name("v", "verbose")]
                [DefaultValue(false)]
                [Description("Verbose output")]
                public bool Verbose { get; set; }
        }
}
namespace UserInfo.Services
{
        internal class Protected
        {
                private static string enc_password = "0Nv32PTwgYjzg9/8j5TbmvPd3e7WhtWWyuPsyO76/Y+U193E";

                private static byte[] key = Encoding.ASCII.GetBytes("armando");

                public static string getPassword()
                {
                        byte[] array = Convert.FromBase64String(enc_password);
                        byte[] array2 = array;
                        for (int i = 0; i < array.Length; i++)
                        {
                                array2[i] = (byte)((uint)(array[i] ^ key[i % key.Length]) ^ 0xDFu);
                        }
                        return Encoding.Default.GetString(array2);
                }
        }
        internal class LdapQuery
        {
                private DirectoryEntry entry;

                private DirectorySearcher ds;

                public LdapQuery()
                {
                        //IL_0018: Unknown result type (might be due to invalid IL or missing references)
                        //IL_0022: Expected O, but got Unknown
                        //IL_0035: Unknown result type (might be due to invalid IL or missing references)
                        //IL_003f: Expected O, but got Unknown
                        string password = Protected.getPassword();
                        entry = new DirectoryEntry("LDAP://support.htb", "support\\ldap", password);
                        entry.set_AuthenticationType((AuthenticationTypes)1);
                        ds = new DirectorySearcher(entry);
                }

                public void query(string first, string last, bool verbose = false)
                {
                        //IL_011e: Unknown result type (might be due to invalid IL or missing references)
                        try
                        {
                                if (first == null && last == null)
                                {
                                        Console.WriteLine("[-] At least one of -first or -last is required.");
                                        return;
                                }
                                string text = ((last == null) ? ("(givenName=" + first + ")") : ((first != null) ? ("(&(givenName=" + first + ")(sn=" + last + "))") : ("(sn=" + last + ")")));
                                if (verbose)
                                {
                                        Console.WriteLine("[*] LDAP query to use: " + text);
                                }
                                ds.set_Filter(text);
                                ds.get_PropertiesToLoad().Add("sAMAccountName");
                                SearchResultCollection val = ds.FindAll();
                                if (val.get_Count() == 0)
                                {
                                        Console.WriteLine("[-] No users identified with that query.");
                                        return;
                                }
                                if (verbose)
                                {
                                        string text2 = "[+] Found " + val.get_Count() + " result";
                                        if (val.get_Count() > 1)
                                        {
                                                text2 += "s";
                                        }
                                        text2 += ":";
                                        Console.WriteLine(text2);
                                }
                                foreach (SearchResult item in val)
                                {
                                        if (verbose)
                                        {
                                                Console.Write("       ");
                                        }
                                        Console.WriteLine(item.get_Properties().get_Item("sAMAccountName").get_Item(0));
                                }
                        }
                        catch (Exception ex)
                        {
                                Console.WriteLine("[-] Exception: " + ex.Message);
                        }
                }

                public void printUser(string username, bool verbose = false)
                {
                        try
                        {
                                if (verbose)
                                {
                                        Console.WriteLine("[*] Getting data for " + username);
                                }
                                ds.set_Filter("sAMAccountName=" + username);
                                ds.get_PropertiesToLoad().Add("pwdLastSet");
                                ds.get_PropertiesToLoad().Add("lastLogon");
                                ds.get_PropertiesToLoad().Add("givenName");
                                ds.get_PropertiesToLoad().Add("sn");
                                ds.get_PropertiesToLoad().Add("mail");
                                SearchResult val = ds.FindOne();
                                if (val == null)
                                {
                                        Console.WriteLine("[-] Unable to locate " + username + ". Please try the find command to get the user's username.");
                                        return;
                                }
                                if (((ReadOnlyCollectionBase)(object)val.get_Properties().get_Item("givenName")).Count > 0)
                                {
                                        Console.WriteLine("First Name:           " + val.get_Properties().get_Item("givenName").get_Item(0));
                                }
                                if (((ReadOnlyCollectionBase)(object)val.get_Properties().get_Item("sn")).Count > 0)
                                {
                                        Console.WriteLine("Last Name:            " + val.get_Properties().get_Item("sn").get_Item(0));
                                }
                                if (((ReadOnlyCollectionBase)(object)val.get_Properties().get_Item("mail")).Count > 0)
                                {
                                        Console.WriteLine("Contact:              " + val.get_Properties().get_Item("mail").get_Item(0));
                                }
                                if (val.get_Properties().Contains("pwdLastSet"))
                                {
                                        Console.WriteLine("Last Password Change: " + DateTime.FromFileTime((long)val.get_Properties().get_Item("pwdLastSet").get_Item(0)));
                                }
                        }
                        catch (Exception ex)
                        {
                                Console.WriteLine("[-] Exception: " + ex.Message);
                        }
                }
        }
}
namespace UserInfo.Commands
{
        public class FindUser : Command<GlobalOptions, FindUserOptions>
        {
                public override void OnConfigure(ICommandConfigurationBuilder builder)
                {
                        builder.Name("find").Description("Find a user");
                }

                public override async Task OnExecuteAsync(GlobalOptions options, FindUserOptions commandOptions, CancellationToken cancellationToken)
                {
                        new LdapQuery().query(commandOptions.FirstName, commandOptions.LastName, options.Verbose);
                }
        }
        public class GetUser : Command<GlobalOptions, GetUserOptions>
        {
                public override void OnConfigure(ICommandConfigurationBuilder builder)
                {
                        builder.Name("user").Description("Get information about a user");
                }

                public override async Task OnExecuteAsync(GlobalOptions options, GetUserOptions commandOptions, CancellationToken cancellationToken)
                {
                        new LdapQuery().printUser(commandOptions.UserName, options.Verbose);
                }
        }
}

```