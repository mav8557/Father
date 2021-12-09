# Father

![nil is goated](https://img.shields.io/badge/nil-goated-green)

<img src="https://images-wixmp-ed30a86b8c4ca887773594c2.wixmp.com/f/1f55d65b-4d63-4900-8368-0b4a22671258/d4vlvsp-f0887625-7a55-42e8-b8a4-b25cd93609e7.png/v1/fill/w_900,h_740,q_75,strp/Father_knd_by_davidalex-d4vlvsp.png?token=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJ1cm46YXBwOjdlMGQxODg5ODIyNjQzNzNhNWYwZDQxNWVhMGQyNmUwIiwic3ViIjoidXJuOmFwcDo3ZTBkMTg4OTgyMjY0MzczYTVmMGQ0MTVlYTBkMjZlMCIsImF1ZCI6WyJ1cm46c2VydmljZTppbWFnZS5vcGVyYXRpb25zIl0sIm9iaiI6W1t7InBhdGgiOiIvZi8xZjU1ZDY1Yi00ZDYzLTQ5MDAtODM2OC0wYjRhMjI2NzEyNTgvZDR2bHZzcC1mMDg4NzYyNS03YTU1LTQyZTgtYjhhNC1iMjVjZDkzNjA5ZTcucG5nIiwid2lkdGgiOiI8PTkwMCIsImhlaWdodCI6Ijw9NzQwIn1dXX0.JZNrVpMjFfrYAzl6unubFKGkKE33V1o-nlUHcHFXFgI" height="370" width="450">


## Overview

***Father*** is a short LD_PRELOAD rootkit for Linux. It's designed to be used in a competition environment, and has various standard features:</br>

* Network hiding
* File hiding
* Process hiding
* Local privilege escalation
* Remote accept() hook backdoor
* Time/logic bomb component
* GnuPG signature interception
* Anti-detection

## Installation

### Dependencies
To install Father, download the source code and change the configuration options to reflect your desired values. You can set the INSTALL_LOCATION to a file with the STRING prefix to hide the kit on disk.

To compile the kit you'll need to download libgcrypt on your computer. The dynamic linker will resolve all libgcrypt calls (like from GnuPG) to our dynamic library.


## Operation

### Priv-Esc 

To escalate privileges, just run a setuid program like *sudo* or *gpasswd* from the command prompt with your specified environment variable set. While in the shell you'll possess your magic GID and rootkit functions will be disabled, giving you unrestricted access to the system. Any processes spawned will be hidden from utilities like ps. This should work for most binaries.

```bash
$ Father=a gpasswd

Enjoy the shell!

root@sectorv:~# 
```

### accept() backdoor

To use the accept backdoor, connect to a listening TCP socket on the system from the defined source port. If everything is working you'll be prompted to authenticate with your password and on complete will be presented with a bind shell.  It will inherit the permissions of the running process, and if possible hide itself from the process list. This behavior can be changed to a reverse shell over the hidden port by uncommenting the relevant code block in the source.

```bash
root@kali:~# ncat $IP 22 -p $SOURCEPORT 


AUTHENTICATE: father

```

### GnuPG Signature Tampering

This is very easy to implement, but meant moreso as a proof of concept. Since GnuPG is a dynamically linked program, we can intercept the calls it makes to its own library libgcrypt and change the return values. If you load the kit and then run any libgcrypt signature verification you'll receive a succcessful result, regardless of file or signature content. In theory this can be expanded to backdoor other operations like key reading and generation, or encryption/decryption.


### remove_preload.asm

remove_preload.asm is a short assembly program that unlinks /etc/ld.so.preload. The kit can be removed from the backdoor shell, but this provides a smaller and more easily scripted way to do so. It can be run in a loop by a blue team to prevent installation of most LD_PRELOAD based malware.

### IOCs

* ssdeep: 192:RRhX15E5vzeV88cAgVrJbcvJuxI61ttgjnaJcac0tQCmOuJ/nwfoTnhawnh5HSh:FsvKrcAgrpAq/OaJcacK9BcnEwK
