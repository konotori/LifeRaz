# Description

LifeRaz is the Scaning and Exploiting Vulnerable Tool for website using Liferay Portal code by Python 3

With Java Deserialization vulnerable, this tool use [ysoserial](https://github.com/frohoff/ysoserial) to generate payload

|Tested on|.
|---|---
|Ubuntu|Working
|Windows|Working.

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

[![](https://media.giphy.com/media/UrsOqBQ0nQJQDzECBZ/giphy.gif)
