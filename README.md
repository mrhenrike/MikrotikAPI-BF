# Mikrotik RouterOS API Bruteforce Tool
[![Build Status](https://travis-ci.org/Wooowe/Mikrotik-rust.svg?branch=master)](https://travis-ci.org/Wooowe/Mikrotik-rust)
[![Latest Version](https://img.shields.io/pypi/v/RouterOS-api.svg)](https://pypi.python.org/pypi/RouterOS-api/)
![Supported Python versions](https://img.shields.io/badge/Python-3-blue)
![Wheel Status](https://img.shields.io/pypi/wheel/RouterOS-api.svg)
[![License](https://img.shields.io/pypi/l/RouterOS-api.svg)](https://github.com/mrhenrike/MikrotikAPI-BF/blob/master/LICENSE)

```sh
        __  __ _ _              _   _ _        _    ____ ___      ____  _____
        |  \/  (_) | ___ __ ___ | |_(_) | __   / \  |  _ \_ _|    | __ )|  ___|
        | |\/| | | |/ / '__/ _ \| __| | |/ /  / _ \ | |_) | |_____|  _ \| |_
        | |  | | |   <| | | (_) | |_| |   <  / ___ \|  __/| |_____| |_) |  _|
        |_|  |_|_|_|\_\_|  \___/ \__|_|_|\_\/_/   \_\_|  |___|    |____/|_|


                     Mikrotik RouterOS API Bruteforce Tool 1.2
                     André Henrique (X / Linkedin: @mrhenrike)
            Please report tips, suggests and problems to X or LinkedIn
                    https://github.com/mrhenrike/MikrotikAPI-BF
```

**Brute force attack tool on Mikrotik box credentials exploiting API requests.**
- This is a tool developed in Python 3 that performs bruteforce attacks (dictionary-based) systems against Mikrotik RouterOS and Cloud Hosted Router (ver. 6.x or newer) which have the API interface port open (mormally port 8728 for non-SSL, 8729 for SSL). Currently has all the basic features of a tool to make dictionary-based attacks, but in the future we plan to incorporate other options.
- This tool is a fork of the MKBrutos Project (original project). As the original tool stopped being updated, many changes occurred in Mikrotik's boxes, including and its API requests. This current project is the improvement or "an upgrade" of MKBRUTUS using the new Mikrotik APIs. 

> **WARNING** for old users: 
> Project has changes it's structure and import signature.
> So it is important to always perform a "git pull" or download the latest release again.

## Features
- Brute-force attack using a password wordlist
- SSL support (via `--ssl` flag)
- Auto delay between attempts
- Clear and structured terminal output
- Modular code for easy integration and customization

## Requirements
- Python 3.x
- No external dependencies required
- Local modules: `_api.py`, `_log.py`

## Download latest version
```sh
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
```

## Usage
```bash
python mikrotikapi-bf.py -t <target_ip> -d <wordlist.txt> [-u <user>] [-p <port>] [-s <seconds>] [--ssl]
```

### Example
```bash
python mikrotikapi-bf.py -t 192.168.88.1 -d ./passwords.txt --ssl
```

## Arguments
| Option       | Description                              | Default         |
|--------------|------------------------------------------|-----------------|
| `-t`         | Mikrotik IP address                      | *Required*      |
| `-d`         | Path to password wordlist                | *Required*      |
| `-u`         | Username to authenticate                 | `admin`         |
| `-p`         | API non-ssl port                         | `8728`          |
| `-s`         | Delay between attempts (in seconds)      | `1`             |
| `--ssl`      | Use SSL for RouterOS API (port 8729)     | *Disabled*      |


## Outputs
#### If login successfull
```sh
[*] Starting bruteforce attack...
---------------------------------
[-] Trying with default credentials on RouterOS...
[-] Default RouterOS credentials were unsuccessful, trying with 5 passwords in list...

[-] Trying 1 of 5 Passwords - Current: 123456
[+] Login successful!!! User: admin Password: 123456
__________________________________________
Elapsed Time: 0.4 sec | Passwords Tried: 1
```
#### If login failed
```sh
[*] Starting bruteforce attack...
---------------------------------
[-] Trying with default credentials on RouterOS...
[-] Default RouterOS credentials were unsuccessful, trying with 5 passwords in list...

[-] Trying 1 of 5 Passwords - Current: teste
[-] Trying 2 of 5 Passwords - Current: 12341234
[-] Trying 1 of 5 Passwords - Current: teste
[-] Trying 2 of 5 Passwords - Current: 12341234
[-] Trying 3 of 5 Passwords - Current: asdflaskjd1234
[-] Trying 4 of 5 Passwords - Current: 123asdfas
[-] Trying 5 of 5 Passwords - Current: 12412342
[-] Trying 6 of 5 Passwords - Current: 456365

[*] ATTACK FINISHED! No suitable credentials were found. Try again with a different wordlist.
___________________________________________
Elapsed Time: 10.1 sec | Passwords Tried: 5
```

## Bug Fix
#### 2023/Feb/02 (Contributor: https://github.com/Dmitriusan)
* bug fix for empty list response
* added retries on socket timeout when opening the connection
* added ability to autosave current progress and continue after program restart. Example: `python3 mikrotikapi-bf.py -t 192.168.0.1 -d /tmp/passwords.txt -a /tmp/autosave.json` 

- - -

### Based from:
+ [Mikrotik API Python3](https://wiki.mikrotik.com/wiki/Manual:API_Python3)
+ [Mikrotik Tools](https://github.com/0ki/mikrotik-tools)
+ [mkbrutusproject / MKBRUTUS](http://mkbrutusproject.github.io/MKBRUTUS/)
+ [DEssMALA / RouterOS_API](https://github.com/DEssMALA/RouterOS_API)

### Scenario Current (Described by Federico Massa and Ramiro Caire)
Mikrotik brand devices (www.mikrotik.com), which runs the RouterOS operative system, are worldwide known and popular with a high networking market penetration. Many companies choose them as they are a great combination of low-cost and good performance. RouterOS can be also installed on other devices such as PC em Virtual Environment.

This system can be managed by the following ways:
- Telnet
- SSH
- Winbox (proprietary GUI of Mikrotik)
- HTTP
- API

Many network sysadmins choose to close Telnet, SSH and HTTP ports, leaving the Winbox port open for graphical management or to another client (developed by third parties) which uses the RouterOS API port, such as applications for Android (managing routers and Hotspots) or web front-ends. 

> At this point, **MikrotikeAPI-BF** comes into **play ;)**

Both, Winbox and API ports uses a RouterOS proprietary protocol to "talk" with management clients.

It is possible that in the midst of a pentesting project, you can find the ports 8291/TCP (Winbox default) and 8728/TCP (API Non-SSL default) open and here we have a new attack vector.

Because the port 8291/TCP is only possible to authenticate using the Winbox tool (at least by now ;), we realized the need of develop a tool to perform dictionary-based attacks over the API port (8728/TCP), in order to allow the pentester to have another option to try to gain access

## License

MIT License