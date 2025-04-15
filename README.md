# Mikrotik RouterOS API Bruteforce Tool
[![Latest Version](https://img.shields.io/pypi/v/RouterOS-api.svg)](https://pypi.python.org/pypi/RouterOS-api/)
![Supported Python versions](https://img.shields.io/badge/Python-3-blue)
![Wheel Status](https://img.shields.io/pypi/wheel/RouterOS-api.svg)
[![License](https://img.shields.io/pypi/l/RouterOS-api.svg)](https://github.com/mrhenrike/MikrotikAPI-BF/blob/master/LICENSE)

## Description
MikrotikAPI-BF is a Python-based brute-force tool designed to test Mikrotik RouterOS credentials via its API (port 8728) and validate successful logins against additional services such as FTP.

> **ALERT**:
> This tool was crafted for educational, research, and auditing purposes in penetration testing labs, red teaming environments, and training exercises.

> **WARNING**:
> Project has changes it's structure and import signature.
> So it is important to always perform a "git pull" or download the latest release again.

## Features
- Supports combo dictionary (user:pass)
- Accepts single or multiple users/passwords via CLI or file
- Optional multi-threading (default: 2, max: 15)
- Optional service validation (only FTP): `--validate ftp`
- Color-coded CLI logs with `--verbose` and `--verbose-all`
- Supports SSL connection for secure RouterOS APIs
- Clean, deduplicated output table with detected services per credential
- Verbosity toggles for clean or full logging experience

## Python Compatibility
This tool supports:

- ✅ Python 3.8 to 3.12 — Fully supported and tested
- ⚠️ Python 3.6/3.7 — May work, but not officially tested
- ❌ Python 3.13+ — Not supported due to removal of `telnetlib`

> Tip: Use `python3.12` with a virtual environment for guaranteed compatibility or install the python v3.12.2 in your machine via `install-python-3.12.sh` without substitute the python v3.13+.

### 🐍 Installing Python 3.12.x on Kali Linux and Windows (Without Removing Python 3.13.x)

Kali Linux ships with Python 3.13.x by default, which may cause compatibility issues with some tools — including this one. Below is a clean way to install **Python 3.12.x side-by-side**, without breaking the system or affecting existing system dependencies.

#### 🚀 Quick Setup Using the Provided Script for Kali Linux

Use the `install-python-3.12.sh` script included in this repository:

```bash
chmod +x install-python-3.12.sh
./install-python-3.12.sh
```

#### 🚀 Quick Setup Using the Provided Script for Windows Systems

Use the `install-python-3.12.ps1` script included in this repository:

```powershell
# Open powershell with Admin-mode and surf until path where downloaded the script, for example:
Set-ExecutionPolicy RemoteSigned
cd "C:\Users\YOURUSER\Downloads"
.\install-python-3.12.ps1
```

To install all dependencies:
```bash
pip install -r requirements.txt
```

## Supported Platforms
- ✅ Windows
- ✅ Linux (Kali, Parrot, Ubuntu, etc)
- ✅ macOS

## Usage
```bash
python mikrotikapi-bf.py -t <TARGET> -U admin -P password123
```

### Options
```
-t, --target       Mikrotik IP address (required)
-T, --port         Mikrotik API port (default: 8728)
-U, --user         Single username
-P, --passw        Single password
-u, --userlist     Path to user wordlist
-p, --passlist     Path to password wordlist
-d, --dictionary   Path to user:pass combo wordlist
-s, --seconds      Delay between attempts (default: 1s)
--ssl              Use SSL API (port 8729)
--threads          Number of threads (default: 2, max: 15)
--validate         Validate successful logins on services (ftp,...)
-v, --verbose      Enable FAIL/WARN logs
-vv, --verbose-all Enable DEBUG/ERROR logs
```

### Example 1: Simple Bruteforce
```bash
python mikrotikapi-bf.py -t 192.168.88.1 -U admin -p passwords.txt
```

### Example 2: Using a combo file
```bash
python mikrotikapi-bf.py -t 192.168.88.1 -d creds.txt
```

### Example 3: Bruteforce and FTP Validation
```bash
python mikrotikapi-bf.py -t 192.168.88.1 -d creds.txt --validate ftp
```

## Output Example
```
## CREDENTIAL(S) EXPOSED ##
ORD | USERNAME   | PASSWORD     | SERVICES
----+------------+--------------+------------------
001 | admin      | qwerty123    | api, ftp
002 | manager    | mikrotik2024 | api
```

## Based from
+ [Mikrotik API Python3](https://wiki.mikrotik.com/wiki/Manual:API_Python3)
+ [mkbrutusproject / MKBRUTUS](http://mkbrutusproject.github.io/MKBRUTUS/)
+ [DEssMALA / RouterOS_API](https://github.com/DEssMALA/RouterOS_API)

## Scenario Current
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
MIT License - see [LICENSE](LICENSE) file.

## Author
- André Henrique:
  - LinkedIn [@mrhenrike](https://www.linkedin.com/in/mrhenrike)
  - Instagram: [@uniaogeek](https://instagram.com/uniaogeek)
  - X: [@mrhenrike](https://x.com/mrhenrike)