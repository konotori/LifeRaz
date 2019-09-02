# Description

LifeRaz is the Scaning and Exploiting Vulnerable Tool for website using Liferay Portal code by Python 3

With Java Deserialization Vulnerable, this tool use [ysoserial](https://github.com/frohoff/ysoserial) to generate payload

|Tested on|.
|---|---
|Ubuntu|Working

## Vulnerabilities
|Name|Description
|---|---
|LPS-27146|Guests can view names of all Liferay users
|LPS-26935|All JSON web services are accessible without authentication 
|LPS-64441|Java Serialization Vulnerability

# Disclaimer
This software has been created purely for the purposes of academic research and for the development of effective defensive techniques, and is not intended to be used to attack systems except where explicitly authorized. Project maintainers are not responsible or liable for misuse of the software. Use responsibly.

# Installation


```
git clone https://github.com/tungto2006/LifeRaz.git; cd LifeRaz; pip3 install -r requirements.txt
```


# Usage

Run with **sudo** privileges

```
                     | |      (_)  / _|        |  __ \               
                     | |       _  | |_    ___  | |__) |   __ _   ____
                     | |      | | |  _|  / _ \ |  _  /   / _` | |_  /
                     | |____  | | | |   |  __/ | | \ \  | (_| |  / / 
                     |______| |_| |_|    \___| |_|  \_\  \__,_| /___|
    
                 ====] Liferay Portal Scaning and Exploiting tool [====                 
                             ====] Version: BETA 1.0.0 [====                              
                                       @Code by ...                                       

lse> help

Core Commands
=============

Command         Description
-------         -----------
help            Print out help
scan            Scan url information and vulnerability
exploit         Exploit vulnerability
clr             Clear screen
clean           Clean log files
exit            Exit framework

lse> scan
lse(scan)> help

Core Commands
=============
set                  Set url to scan
execute              Execute scanning
show options         Show options of scanning
clr                  Clear screen
back                 Back to home
clean                Clean log files
exit                 Exit framework

lse(scan)> back
lse> exploit
lse(exploit)> help

Core Commands
=============
show [option]        Show information of payload
                     [all] - List payloads
                     [order] - Information of payload
use                  Choose payload to exploit
clr                  Clear screen
back                 Back to home
clean                Clean log files
exit                 Exit framework

```

# Example
## Scan
![](https://i.ibb.co/2WkFN63/Screenshot-from-2019-08-21-22-06-39.jpg)

