# Mikrotik API Brute-force Tool
[![Build Status](https://travis-ci.org/socialwifi/RouterOS-api.svg?branch=master)](https://travis-ci.org/socialwifi/RouterOS-api)
[![Latest Version](https://img.shields.io/pypi/v/RouterOS-api.svg)](https://pypi.python.org/pypi/RouterOS-api/)
![Supported Python versions](https://img.shields.io/badge/Python-3-blue)
![Wheel Status](https://img.shields.io/pypi/wheel/RouterOS-api.svg)
[![License](https://img.shields.io/pypi/l/RouterOS-api.svg)](https://github.com/mrhenrike/MikrotikAPI-BF/blob/master/LICENSE)

**Brute force attack tool on Mikrotik box credentials exploiting API requests.**

> **WARNING** for old users: 
> Project has changes it's structure and import signature.
> So it is important to always perform a "git pull" or download the latest release again.

#### Features:
* Easy to use;
* Standard RouterOS API syntax;
* SSL not-included (is need more tests);
* Verbose.
- - -
## Dependences
```sh
sudo apt-get install python3-pip libglib2.0-dev -y
sudo python3 -m pip install laiarturs-ros-api
```
## Download
```sh
wget -c https://github.com/mrhenrike/MikrotikAPI-BF/archive/master.zip -O MikrotikAPI-BF.zip \
  && unzip MikrotikAPI-BF.zip \
  && rm -f MikrotikAPI-BF.zip
```
## Usage
```sh
    OPTIONS
         -t, --target            RouterOS target
         -p, --port              RouterOS port (default 8728)
         -u, --user              User name (default admin)
         -h, --help              This help
         -d, --dictionary        Password dictionary
         -s, --seconds           Delay seconds between retry attempts (default 1)
         -q, --quiet             Quiet mode

    EXAMPLE
         python3 mikrotikapi-bf.py -t 192.168.0.200 -u manager -p 1337 -d /tmp/passwords.txt -s 5
         python3 mikrotikapi-bf.py -t 192.168.0.1 -d /tmp/passwords.txt
```
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
- - -

### Based from:
+ [Mikrotik API Python3](https://wiki.mikrotik.com/wiki/Manual:API_Python3)
+ [Mikrotik Tools](https://github.com/0ki/mikrotik-tools)
+ [mkbrutusproject / MKBRUTUS](http://mkbrutusproject.github.io/MKBRUTUS/)
+ [DEssMALA / RouterOS_API](https://github.com/DEssMALA/RouterOS_API)
