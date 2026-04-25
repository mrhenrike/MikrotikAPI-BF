# MikrotikAPI-BF v3.10.0

[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.10.0-red.svg)](https://github.com/mrhenrike/MikrotikAPI-BF/releases/tag/v3.10.0)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](README.md)
[![Wiki](https://img.shields.io/badge/Wiki-GitHub-orange)](https://github.com/mrhenrike/MikrotikAPI-BF/wiki)
[![PyPI](https://img.shields.io/badge/pip-mikrotikapi--bf-blue)](https://pypi.org/project/mikrotikapi-bf/)
[![CodeQL](https://github.com/mrhenrike/MikrotikAPI-BF/actions/workflows/codeql.yml/badge.svg)](https://github.com/mrhenrike/MikrotikAPI-BF/actions/workflows/codeql.yml)

**RouterOS Attack & Exploitation Framework** — credential brute-force, **100 CVE/EDB PoC exploits**, 8-phase automated security audit, MAC-Server Layer-2 discovery, offline credential decoders, NPK analyzer, CVE scanner, SARIF CI/CD export, Nmap NSE scripts, multi-target, stealth, REST/API/Winbox/FTP/SSH/Telnet/SMB/SNMP/BFD/OSPF vectors.

**Portuguese (pt-BR):** [README.pt-BR.md](README.pt-BR.md) · **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) · **Code of Conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) · **Security:** [SECURITY.md](SECURITY.md)

---

## ✨ Key Features

### 🔐 Authentication & Brute-Force
- **RouterOS API** (TCP 8728/8729) — full binary protocol implementation (6.x MD5 challenge + 7.x plaintext)
- **REST API** over HTTP/HTTPS (TCP 80/443) — Basic Auth brute-force
- **MAC-Telnet** (TCP 20561) — Layer-2 proprietary protocol (no IP needed)
- **Multi-target** (`--target-list / -T`) — scan from file, sequential engine per target
- **Threading** — up to 15 workers (`--threads N`)

### 🔍 CVE Scanner & Exploit Engine
- **100 exploit classes** — 27 CVEs + 5 design/config findings + 13 Exploit-DB PoCs + novel research PoCs
- **Pre-auth exploits** — Winbox (CVE-2018-14847, CVE-2018-10066), HTTP traversal, SNMP, SMB, BFD, OSPF, DNS
- **Post-auth exploits** — Scheduler RCE, Container escalation, FOISted, WireGuard key extraction, packet sniffer wiretapping, SSRF via tool/fetch, REST path traversal, scheduler command injection
- **SSH Jailbreak** — RouterOS root shell via SSH backup patching (ROS 2.9.8–6.41rc56)
- **Winbox credential decryption** — enhances CVE-2018-14847 with DAT file decryption
- **Version-aware** — CVE database maps applicability to detected RouterOS version
- **`--scan-cve`** — standalone CVE scan (no brute-force needed)
- **`--run-exploit <CVE_ID>`** — run a specific exploit PoC by ID (v3.10.0+)

### 🌐 Winbox CVE Coverage (TCP 8291)
- **CVE-2018-14847** — Credential disclosure (Chimay-Red / EternalWink) — pre-auth file read
- **CVE-2018-10066** — Authentication bypass / directory traversal
- **CVE-2021-27263** — Auth bypass (RouterOS 7.0.x)
- **CVE-2018-14847-MAC** — Same exploit delivered via MNDP Layer-2 discovery
- **NSE script** — `nse/mikrotik-winbox-cve-2018-14847.nse` (Nmap integration)

> ℹ️ Winbox **credential brute-force** via the proprietary Winbox GUI protocol is not implemented (no reliable portable auth library). Use API port 8728 for brute-force. All **Winbox CVE exploits** (pre-auth file read, bypass) are fully implemented.

### 🛰️ MAC-Server / Layer-2 Discovery (v3.3.0+)
- **MNDP broadcast** (UDP 20561) — discovers devices even without IP
- **MAC-Telnet brute-force** (TCP 20561) — proprietary MAC-Telnet auth
- **CVE-2018-14847-MAC** — Winbox credential disclosure via MNDP-discovered devices
- **L2 constraint** — requires same broadcast domain

### 🔓 Offline Credential Decoders (v3.5.0+)
Based on [mikrotik-tools](https://github.com/0ki/mikrotik-tools) by Kirils Solovjovs, ported to Python 3:
- **`--decode-userdat`** — decode `user.dat` after CVE-2018-14847 extraction (XOR with MD5 key)
- **`--decode-backup`** — extract `.backup` archive + auto-decode credentials
- **`--decode-supout`** — list sections in `supout.rif` diagnostic files
- **`--analyze-npk`** — NPK package analyzer (CVE-2019-3977 vector)

### 🗺️ Nmap NSE Scripts (v3.6.0+)
Five Lua scripts in `nse/` for Nmap integration:
- `mikrotik-routeros-version.nse` — fingerprint RouterOS from HTTP/API/Winbox
- `mikrotik-api-brute.nse` — full API brute-force (6.x MD5 + 7.x plaintext auth)
- `mikrotik-default-creds.nse` — test default/empty creds on all interfaces
- `mikrotik-api-info.nse` — authenticated info dump (users, services, firewall)
- `mikrotik-winbox-cve-2018-14847.nse` — Winbox credential disclosure check

### 🎯 Wordlists
- Compatible with [mrhenrike/WordListsForHacking](https://github.com/mrhenrike/WordListsForHacking)
- Includes `labs_mikrotik_pass.lst` (MikroTik-specific), `labs_passwords.lst`, `labs_users.lst`
- Smart wordlist engine with target-informed combinations

### 🛡️ Automated Security Audit (v3.10.0+)
- **`--audit`** — full 8-phase security audit via REST API (no brute-force needed)
- Phase 1: System enumeration (identity, resource, packages, health)
- Phase 2: Service & network mapping (ip/service, firewall, interfaces)
- Phase 3: User & credential audit (blank password, default creds)
- Phase 4: REST API injection testing (scheduler, path traversal, SSRF)
- Phase 5: Winbox protocol probing (port 8291, M2 banner)
- Phase 6: SNMP analysis (default communities)
- Phase 7: Undocumented/debug endpoint discovery
- Phase 8: Configuration export & firewall audit
- Generates markdown report + raw JSON + SARIF

### 🔄 Sessions, Stealth & Export
- **Persistent sessions** — resume interrupted attacks (`--resume`)
- **Stealth mode** — Fibonacci delays, User-Agent rotation (`--stealth`)
- **Progress bar** — ETA and speed display (`--progress`)
- **Export** — JSON, CSV, XML, TXT, **SARIF v2.1.0** (`--export-all` / `--export sarif`)
- **SARIF** — OASIS Static Analysis Results Interchange Format for CI/CD pipelines (v3.10.0+)
- **Proxy** — SOCKS5/HTTP proxy support (`--proxy socks5://...`)

---

## 🚀 Quick Start

### Install via pip (recommended)

```bash
# Latest stable release from PyPI
pip install mikrotikapi-bf

# Upgrade to the latest version
pip install --upgrade mikrotikapi-bf

# Verify installation
mikrotikapi-bf --help
mikrotikapi-bf --nse-path    # prints bundled NSE scripts directory for Nmap
```

> **NSE scripts** are installed automatically to Nmap's scripts directory during `pip install`.  
> To install them manually: `mikrotikapi-install-nse`

### Install from source (development)

```bash
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
pip install -e .          # editable install — includes NSE auto-install hook
# or without the hook:
pip install -r requirements.txt
python mikrotikapi-bf.py --help
```

### One-liners

```bash
# Basic brute-force
python mikrotikapi-bf.py -t 192.168.1.1 -U admin -d wordlists/passwords.lst

# Username + password lists
python mikrotikapi-bf.py -t 192.168.1.1 -u users.lst -p passwords.lst

# Multi-target from file
python mikrotikapi-bf.py -T targets.lst -d passwords.lst --threads 5

# Full CVE scan (authenticated)
python mikrotikapi-bf.py -t 192.168.1.1 --scan-cve --all-cves -U admin -P pass

# Run specific exploit by CVE ID
python mikrotikapi-bf.py -t 192.168.1.1 --run-exploit CVE-2018-14847

# Full 8-phase security audit with SARIF output
python mikrotikapi-bf.py -t 192.168.1.1 --audit --export sarif -U admin -P pass

# Full pentest run
python mikrotikapi-bf.py \
  -t 192.168.1.1 \
  -u wordlists/users.lst -p wordlists/passwords.lst \
  --validate ftp,ssh,telnet \
  --stealth --fingerprint --progress --export-all \
  --threads 5 -vv

# Decode user.dat after CVE-2018-14847 extraction
python mikrotikapi-bf.py --decode-userdat user.dat --decode-useridx user.idx

# Layer-2 MAC-Server attack
python mikrotikapi-bf.py --mac-discover --mac-brute -d passwords.lst
```

### Nmap NSE Usage

```bash
# Install NSE scripts
cp nse/*.nse /usr/share/nmap/scripts/ && nmap --script-updatedb

# Full discovery
nmap -p 80,8291,8728 --script "mikrotik-*" 192.168.1.0/24

# Check CVE-2018-14847
nmap -p 8291 --script mikrotik-winbox-cve-2018-14847 192.168.1.1

# Brute-force API
nmap -p 8728 --script mikrotik-api-brute \
  --script-args userdb=users.lst,passdb=passwords.lst 192.168.1.1
```

---

## 🗺️ Attack Surface Mapping

### Full Attack Surface — Coverage Status (v3.10.0)

![MikrotikAPI-BF Full Attack Surface Map](img/mikrotik_full_attack_surface.png)

*Complete RouterOS attack surface with MikrotikAPI-BF coverage indicators (✓ covered / ✗ not yet covered)*

---

### 🟠 Access Vectors — Coverage Detail

![Access Vectors Coverage](img/mikrotik_access_vectors.png)

*Orange = Access Vectors. Green ✓ = covered. Red ✗ = not yet covered.*

| Access Vector | Port(s) | Tool Coverage | How |
|--------------|---------|--------------|-----|
| **telnet** | TCP/23 | ✅ Covered | Post-login validation (`--validate telnet`) |
| **ssh** | TCP/22 | ✅ Covered | Post-login validation + EDB-28056 (ROSSSH heap) |
| **web** (WebFig/REST) | TCP/80, 443 | ✅ Covered | REST API brute-force + 10+ CVE/EDB exploits |
| **winbox** | TCP/8291 | ✅ Covered | CVE-2018-14847, CVE-2018-10066, CVE-2021-27263 + NSE script |
| **ftp** | TCP/21 | ✅ Covered | Post-login validation + CVE-2019-3976/3977 + EDB-44450 |
| **samba** (SMB) | TCP/445 | ✅ Covered | CVE-2018-7445, CVE-2022-45315 |
| **mactel** (MAC-Telnet) | TCP/20561 | ✅ Covered | `modules/mac_server.py` — MNDP + brute (v3.3.0+) |
| **dude** | TCP/2210 | ❌ Not covered | The Dude monitoring client — no PoC |
| **setup** (Netinstall) | UDP/5000 | ❌ Not covered | Physical/LAN boot vector |
| **netboot** | TFTP/69 | ❌ Not covered | Physical LAN only |
| **btest** | TCP/2000 | ❌ Not covered | Bandwidth Test — protocol not implemented |
| **dhcp** | UDP/67-68 | ❌ Not covered | Out of scope |
| **console** | RS-232 | ❌ Not covered | Physical serial access only |
| **Woobm-USB** | USB | ❌ Not covered | Physical access only |

**Coverage: 7 / 14 Access Vectors (50%) — all network-accessible vectors covered**

---

### 🔵 Access Targets — Coverage Detail

![Access Targets Coverage](img/mikrotik_access_targets.png)

*Blue = Access Targets. Green ✓ = covered. Red ✗ = not yet covered.*

| Access Target | Component | Coverage | CVEs / Notes |
|--------------|-----------|---------|--------------|
| **filesystem** | `/flash/rw/store/` | ⚠️ Partial | CVE-2018-14847 reads `user.dat`; CVE-2019-3943 path traversal |
| **supout.rif** | Diagnostic file | ✅ Covered | CVE-2023-30799 (FOISted) — priv escalation via supout upload |
| **.npk** | Package files | ✅ Covered | CVE-2019-3977/3976 — arbitrary exec/read via NPK |
| **.backup** | Config backup | ❌ Not covered | No exploit for backup file extraction/abuse |
| **FLASH** | Internal flash | ❌ Not covered | Requires filesystem or physical access |
| **NAND** | NAND storage | ❌ Not covered | Low-level, physical access |
| **HDD** | Hard disk (CHR) | ❌ Not covered | CHR-specific — no direct exploit path |
| **kvm** | Virtual machine | ❌ Not covered | KVM hypervisor — out of scope |

---

## 📄 CLI Reference (All Flags)

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--target` | `-t` | Target IP/hostname | — |
| `--target-list` | `-T` | File with targets (one per line) | — |
| `--user` | `-U` | Single username | admin |
| `--passw` | `-P` | Single password | — |
| `--userlist` | `-u` | Username wordlist file | — |
| `--passlist` | `-p` | Password wordlist file | — |
| `--dictionary` | `-d` | Combo file (`user:pass`) | — |
| `--delay-mode` | — | Delay profile: `high,balanced,stealth,custom` | high |
| `--seconds` | `-s` | Custom delay in seconds (with `--delay-mode custom`) | profile-based |
| `--threads` | — | Thread count (max 300; `>15` requires `--high-threads`) | 2 |
| `--api-port` | — | RouterOS API port | 8728 |
| `--rest-port` | — | RouterOS REST port | 8729 |
| `--http-port` | — | HTTP port | 80 |
| `--ssl` | — | Use HTTPS/API-SSL | false |
| `--ssl-port` | — | HTTPS port | 443 |
| `--validate` | — | Post-login validation (`ftp,ssh,telnet`) | — |
| `--verbose` | `-v` | Show failed attempts | false |
| `--verbose-all` | `-vv` | Full debug | false |
| `--progress` | — | Progress bar + ETA | false |
| `--stealth` | — | Stealth delays + UA rotation | false |
| `--fingerprint` | — | Advanced device fingerprinting | false |
| `--exploit` | — | Run exploit scanner after BF | false |
| `--scan-cve` | — | Standalone CVE scan (no BF) | false |
| `--all-cves` | — | Show all CVEs (ignore version) | false |
| `--run-exploit` | — | Run specific exploit by CVE ID | — |
| `--audit` | — | Full 8-phase security audit via REST | false |
| `--audit-report` | — | Audit report output directory | results |
| `--proxy` | — | Proxy URL (`socks5://...`) | — |
| `--interactive` | — | Start interactive REPL | false |
| `--max-retries` | — | Connection retry count | 1 |
| `--export` | — | Formats: `json,csv,xml,txt,sarif` | — |
| `--export-all` | — | Export to all formats | false |
| `--export-dir` | — | Output directory | results |
| `--resume` | — | Resume previous session | false |
| `--force` | — | Force new session | false |
| `--list-sessions` | — | List saved sessions | — |
| `--mac-discover` | — | MNDP broadcast discovery | false |
| `--mac-brute` | — | Brute via MAC-Telnet | false |
| `--mac-scan-cve` | — | CVE-2018-14847-MAC | false |
| `--mac-iface-ip` | — | Local IP for MNDP | 0.0.0.0 |
| `--decode-userdat` | — | Decode `user.dat` offline | — |
| `--decode-useridx` | — | Companion `user.idx` | — |
| `--decode-backup` | — | Decode `.backup` archive | — |
| `--analyze-npk` | — | Analyze NPK package | — |
| `--decode-supout` | — | List `supout.rif` sections | — |

> **Full guide:** [Wiki — Complete Usage Guide](https://github.com/mrhenrike/MikrotikAPI-BF/wiki/Complete-Usage-Guide) · [pt-BR](https://github.com/mrhenrike/MikrotikAPI-BF/wiki/Complete-Usage-Guide-pt-BR)

---

## 🧭 Attack Surface Coverage by Service

| Service | Port | Brute-Force | CVE/Exploits | NSE Script |
|---------|------|------------|-------------|-----------|
| RouterOS API | TCP/8728 | ✅ Primary target | Brute-force/rate-limit exposure validation | `mikrotik-api-brute.nse` |
| REST API | TCP/80,443 | ✅ HTTP Basic Auth | CVE-2019-3924, 2019-3943, 2023-30799, 2023-30800, 2024-35274 | `mikrotik-default-creds.nse` |
| Winbox | TCP/8291 | ⚠️ Not (no auth lib) | CVE-2018-14847, 2018-10066, 2021-27263 | `mikrotik-winbox-cve-2018-14847.nse` |
| FTP | TCP/21 | ✅ Post-login | CVE-2019-3976, 2019-3977, EDB-44450 | — |
| SSH | TCP/22 | ✅ Post-login | EDB-28056 (ROSSSH) | — |
| Telnet | TCP/23 | ✅ Post-login | — | — |
| SMB | TCP/445 | — | CVE-2018-7445, CVE-2022-45315 | — |
| SNMP | UDP/161 | — | EDB-31102, EDB-6366 | — |
| MAC-Telnet | TCP/20561 | ✅ L2 only | CVE-2018-14847-MAC | — |

---

## 🔎 Full Exploit Coverage (47 entries)

| ID | Title | CVSS | Auth | PoC | Fixed in |
|----|-------|------|------|-----|---------|
| CVE-2018-7445 | SMB Stack Buffer Overflow | 9.8 | No | [EDB-44290](https://www.exploit-db.com/exploits/44290) | 6.41.4 |
| CVE-2018-10066 | Winbox Auth Bypass | 8.1 | No | [EDB-44813](https://www.exploit-db.com/exploits/44813) | 6.42 |
| CVE-2018-14847 | Winbox Credential Disclosure (Chimay-Red) | 9.1 | No | [EDB-45220](https://www.exploit-db.com/exploits/45220) | 6.42.1 |
| CVE-2018-14847-MAC | Winbox via MNDP (Layer-2) | 9.1 | No | — | 6.42.1 |
| CVE-2019-3924 | WWW Firewall/NAT Bypass | 9.8 | No | [EDB-46444](https://www.exploit-db.com/exploits/46444) ✓ | 6.43.12 |
| CVE-2019-3943 | HTTP Path Traversal | 8.8 | No | [EDB-46731](https://www.exploit-db.com/exploits/46731) | 6.43.8 |
| CVE-2019-3976 | NPK Arbitrary File Read | 6.5 | Yes | — | 6.45.7 |
| CVE-2019-3977 | NPK Arbitrary Code Execution | 7.5 | Yes | — | 6.45.7 |
| CVE-2019-3978 | DNS Cache Poisoning | 7.5 | No | [EDB-47566](https://www.exploit-db.com/exploits/47566) | 6.45.7 |
| CVE-2019-3981 | DNS Forwarder MitM | 7.5 | No | — | 6.45.7 |
| CVE-2020-20215 | MPLS Out-of-Bounds Write (DoS) | 7.5 | Yes | — | 6.47 |
| CVE-2020-5720 | UDP Fragment Crash | 7.5 | Yes | — | 6.46.5 |
| CVE-2021-27263 | Winbox Auth Bypass (7.0.x) | 7.5 | No | — | 7.1 |
| CVE-2021-36522 | www Authenticated RCE via Scheduler | 8.8 | Yes | — | 6.49.3 |
| CVE-2021-41987 | RADIUS Client Buffer Overflow | 8.1 | No | — | 6.49.1/7.1 |
| CVE-2022-34960 | Container Privilege Escalation | 8.8 | Yes | — | 7.6 |
| CVE-2022-45313 | SMB Heap Use-After-Free | 8.8 | No | — | 6.49.7/7.6 |
| CVE-2022-45315 | SMB Authenticated Stack Overflow | 8.8 | Yes | [EDB-51451](https://www.exploit-db.com/exploits/51451) | 6.49.7 |
| CVE-2023-30799 | FOISted — supout.rif Privilege Escalation | 9.1 | Yes | — | 6.49.9 |
| CVE-2023-30800 | WWW Stack-Based Buffer Overflow | 8.2 | No | — | 6.49.9 |
| CVE-2024-27887 | OSPF Route Injection | 7.5 | No | — | — |
| CVE-2024-2169 | BFD Reflection/Amplification Loop | 7.5 | No | — | Mitigate |
| CVE-2024-35274 | Authenticated RCE via Scheduler Injection | 8.8 | Yes | — | Pending |
| CVE-2025-6563 | RouterOS 7.x WebFig XSS/Open Redirect | 6.1 | No | — | Pending |
| CVE-2017-20149 | www Password Exposure | 7.5 | No | — | 6.38.5 |
| CVE-2025-61481 | WebFig HTTP Credential Exposure | 7.5 | No | — | Pending |
| CVE-2025-10948 | REST API Stack Buffer Overflow RCE | 9.8 | No | — | Pending |
| MIKROTIK-CONFIG-001 | WireGuard Private Key Exposure | — | Yes | — | Design |
| MIKROTIK-CONFIG-002 | Packet Sniffer Remote Streaming | — | Yes | — | Design |
| MIKROTIK-CONFIG-003 | SSRF via /rest/tool/fetch | — | Yes | — | Design |
| MIKROTIK-CONFIG-004 | Scheduler Command Injection | — | Yes | — | Design |
| MIKROTIK-CONFIG-005 | REST API Path Traversal Probe | — | Yes | — | Design |
| MIKROTIK-JAILBREAK-001 | SSH Backup Patch Root Shell | 9.8 | Yes | — | 6.41rc56 |
| CVE-2018-14847-DECRYPT | Winbox Credential Decryption | 9.1 | No | — | 6.42.1 |
| EDB-31102 | RouterOS 3.x SNMP SET DoS | — | No | [EDB ✓](https://www.exploit-db.com/exploits/31102) | ≤ 3.2 |
| EDB-6366 | RouterOS 3.x SNMP Unauthorized Write | — | No | [EDB ✓](https://www.exploit-db.com/exploits/6366) | ≤ 3.13 |
| EDB-44283/44284 | Chimay-Red Stack Clash RCE (MIPSBE+x86) | 9.8 | No | [EDB](https://www.exploit-db.com/exploits/44283) | < 6.38.4 |
| EDB-44450 | FTP Daemon DoS | — | No | [EDB](https://www.exploit-db.com/exploits/44450) | 6.41.4 |
| EDB-43317 | ICMP DoS (6.40.5) | — | Yes | [EDB](https://www.exploit-db.com/exploits/43317) | 6.40.5 |
| EDB-41752 | RouterBoard DoS (6.38.5) | — | Yes | [EDB](https://www.exploit-db.com/exploits/41752) | 6.38.5 |
| EDB-41601 | ARP Table Overflow DoS | — | No | [EDB](https://www.exploit-db.com/exploits/41601) | All |
| EDB-28056 | ROSSSH sshd Remote Heap Corruption | — | No | [EDB](https://www.exploit-db.com/exploits/28056) | Multiple |
| EDB-24968 | Syslog Server Windows 1.15 BoF DoS | — | No | [EDB ✓](https://www.exploit-db.com/exploits/24968) | Win app |
| EDB-18817 | Generic Router DoS | — | No | [EDB](https://www.exploit-db.com/exploits/18817) | Multiple |
| EDB-52366 | RouterOS 7.19.1 WebFig Reflected XSS | — | No | [EDB](https://www.exploit-db.com/exploits/52366) | 7.19.1 |
| EDB-48474 | Router Monitoring System 1.2.3 SQLi | — | No | [EDB](https://www.exploit-db.com/exploits/48474) | Web app |
| EDB-39817 | DNSmasq/Mikrotik Web Interface SQLi | — | No | [EDB](https://www.exploit-db.com/exploits/39817) | Web app |

> ✓ = EDB Verified | All PoCs are detection-only — no destructive payloads sent.  
> Full guide: [Wiki — EDB Exploit Coverage](https://github.com/mrhenrike/MikrotikAPI-BF/wiki/EDB-Exploit-Coverage)

---

## 📦 Project Layout

```
MikrotikAPI-BF/
├── version.py                    # Canonical version source (edit to bump)
├── mikrotikapi-bf.py             # Main entry point (v3.10.0)
├── pyproject.toml                # pip package definition
├── requirements.txt
├── .env.example                  # Environment variable template (safe to commit)
├── SECURITY.md                   # Vulnerability reporting policy
├── mikrotikapi_bf/               # pip installable package
│   ├── __init__.py
│   └── cli.py                    # Entry point for `mikrotikapi-bf` command
├── nse/                          # Nmap NSE scripts (v3.6.0+)
│   ├── README.md
│   ├── mikrotik-api-brute.nse
│   ├── mikrotik-api-info.nse
│   ├── mikrotik-default-creds.nse
│   ├── mikrotik-routeros-version.nse
│   └── mikrotik-winbox-cve-2018-14847.nse
├── core/                         # Core engine
│   ├── api.py                    # RouterOS binary API protocol
│   ├── apiros_client.py          # Alternative API client (full binary protocol + SSL)
│   ├── cli.py                    # Interactive REPL CLI
│   ├── export.py                 # JSON/CSV/XML/TXT/SARIF export
│   ├── log.py                    # Logging subsystem
│   ├── progress.py               # Progress bar + ETA
│   ├── retry.py                  # Retry + backoff
│   └── session.py                # Persistent session management
├── modules/                      # Feature modules
│   ├── decoder.py                # RouterOS file decoder: user.dat/.backup/supout.rif (v3.6.0)
│   ├── discovery.py              # Network discovery
│   ├── fingerprint.py            # Device fingerprinting (Shodan + REST)
│   ├── mac_server.py             # Layer-2 MNDP discovery + MAC-Telnet (v3.3.0)
│   ├── proxy.py                  # Proxy/SOCKS5 support
│   ├── reports.py                # Report generation
│   ├── stealth.py                # Fibonacci delays + UA rotation
│   └── wordlists.py              # Smart wordlist engine
├── xpl/                          # Exploit/CVE engine
│   ├── auditor.py                # 8-phase automated security audit (v3.10.0)
│   ├── cve_db.py                 # CVE database (100 exploits)
│   ├── exploits.py               # 100 exploit classes
│   ├── npk_decoder.py            # NPK package analyzer (v3.6.0)
│   ├── nvd_shodan.py             # NVD API + Shodan integration
│   ├── offline_analyzer.py       # Offline artifact analyzer
│   └── scanner.py                # Vulnerability scanner
├── tools/                        # Standalone utilities (v3.8.0+)
│   └── binary_analysis.py        # Offline firmware binary analysis (LIEF + Capstone)
├── img/                          # Attack surface diagrams
│   ├── mikrotik_full_attack_surface.png
│   ├── mikrotik_access_vectors.png
│   └── mikrotik_access_targets.png
└── examples/
    ├── example_basic.sh  example_discovery.sh  example_stealth.sh
    └── usernames.txt  passwords.txt  combos.txt
```

---

## 🧱 RouterOS Defenses You Will Encounter

- Session controls and server-side anti-fraud for auth flows
- Request limits and rate-limiting per source (when configured)
- Temporary account lockouts and backoff windows
- Extensive logging (auth failures, rate limiting, HTTP 4xx/5xx)
- IDS/IPS/NAC and WAF-likes in front of HTTP endpoints

> Prefer stealth mode, sensible thread counts, and authorized maintenance windows.

---

## 🛡️ Defensive Mitigations for RouterOS Admins

```routeros
# Disable unused services
/ip service disable telnet,ftp,api

# Restrict API access by source IP
/ip service set api address=10.0.0.0/8

# Disable MAC-Server (L2 exposure)
/tool mac-server set allowed-interface-list=none
/ip neighbor discovery-settings set discover-interface-list=none

# Add firewall to protect management ports
/ip firewall filter
add chain=input connection-state=established,related action=accept
add chain=input src-address=<MGMT-NET>/24 action=accept
add chain=input action=drop
```

---

## 📖 Documentation

| Resource | Link |
|----------|------|
| **GitHub Wiki (en-US)** | [Complete Usage Guide](https://github.com/mrhenrike/MikrotikAPI-BF/wiki/Complete-Usage-Guide) |
| **GitHub Wiki (pt-BR)** | [Guia Completo](https://github.com/mrhenrike/MikrotikAPI-BF/wiki/Complete-Usage-Guide-pt-BR) |
| **EDB Exploit Coverage** | [Wiki — EDB-Exploit-Coverage](https://github.com/mrhenrike/MikrotikAPI-BF/wiki/EDB-Exploit-Coverage) |
| **NSE Scripts Guide** | [nse/README.md](nse/README.md) |
| **Security Policy** | [SECURITY.md](SECURITY.md) |
| **Changelog** | [Releases](https://github.com/mrhenrike/MikrotikAPI-BF/releases) |
| **API Reference** | [docs/API_REFERENCE.md](docs/API_REFERENCE.md) |

---

## 📋 What's New

### v3.10.0 (current)
- **100 CVE/EDB database entries** — comprehensive coverage from 2008 to 2025
- **97 executable exploit classes** — all invocable via `--run-exploit <CVE_ID>` or `--scan-cve --all-cves`
- **VU#375660 formal entry** — author's own brute-force rate-limiting vulnerability (CERT/CC VINCE)
- **2020 memory corruption series** — 21 CVEs covering NULL pointer, OOB write, memcorrupt in console, graphing, sniffer, resolver, lcdstat, wireless, dot1x, bfd, igmp-proxy, detnet, diskd, mactel, netwatch, traceroute
- **Legacy CVE coverage** — CVE-2017-17537/17538, CVE-2015-2350, CVE-2012-6050, CVE-2008-6976
- **13 EDB entries synced** — EDB-31102, EDB-6366, EDB-44283/44284, EDB-44450, EDB-43317, EDB-41752, EDB-41601, EDB-28056, EDB-24968, EDB-18817, EDB-52366, EDB-48474, EDB-39817
- **New exploit classes** — DNS cache poisoning, FTP .rsc overwrite, Winbox user enum, VXLAN bypass, DHCPv6 RCE, bridge2 OOB write, REST ACL bypass, IPv6 FW bypass, hotspot XSS, L2TP downgrade, and more

### v3.9.0
- **`--audit`** — full 8-phase automated security audit via REST API: system enumeration, service mapping, credential audit, injection testing, Winbox probing, SNMP analysis, debug endpoint discovery, firewall audit
- **`--run-exploit <CVE_ID>`** — run any registered exploit PoC directly by ID
- **SARIF v2.1.0 export** — `--export sarif` for CI/CD pipeline integration (GitHub Code Scanning, Azure DevOps, etc.)
- **7 new exploit classes** (v3.7.0–v3.9.0):
  - `Exploit_CVE_2025_61481` — WebFig HTTP credential exposure
  - `Exploit_CVE_2025_10948` — REST API stack buffer overflow RCE
  - `Exploit_SSRF_TOOL_FETCH` — SSRF via /rest/tool/fetch
  - `Exploit_ROUTEROS_JAILBREAK` — SSH backup patch root shell (ROS 2.9.8–6.41rc56)
  - `Exploit_WINBOX_CRED_DECRYPT` — Winbox credential decryption (enhances CVE-2018-14847)
  - `Exploit_SCHED_CMD_INJECTION` — Scheduler command injection via REST API
  - `Exploit_REST_PATH_TRAVERSAL` — REST API path traversal probe
- **`core/apiros_client.py`** — alternative RouterOS API client with full binary protocol, MD5 challenge, and anonymous DH SSL
- **`tools/binary_analysis.py`** — offline firmware binary analysis (LIEF ELF parsing + Capstone disassembly)
- **Interactive CLI** — new `run <CVE_ID> <target>` and `audit <target>` REPL commands
- **Total: 100 exploit classes** across 27 CVEs + 5 config findings + 13 Exploit-DB PoCs + 2 novel research PoCs

### v3.6.0
- **NSE auto-installer** — `mikrotikapi_bf/nse_installer.py` copies NSE scripts to Nmap on Windows/Linux/macOS automatically during `pip install` or `pip install --upgrade`
- **`--install-nse`** flag and `mikrotikapi-install-nse` entry point for manual NSE installation
- **3 more official Nmap MikroTik scripts** bundled: `mikrotik-routeros-brute.nse`, `mikrotik-routeros-username-brute.nse`, `broadcast-mndp-discover.nse`
- **300-thread support** — `--threads N` (up to 300) with mandatory `--high-threads` disclaimer for values > 15
- **Delay profiles for rate-limit validation** — new `--delay-mode high|balanced|stealth|custom` with `high` as default and `custom` via `-s/--seconds`
- **Rate-limiting benchmark snapshot (2026-04-08)** — on CHR 7.22.1 default-fresh: `high=3.70 att/s`, `custom(0.05s)=3.15 att/s`, `balanced=1.85 att/s`, `stealth=0.79 att/s`; sustained `high` run (300 attempts) remained stable at `3.68 att/s`
- **`setup.py` post-install hook** — NSE scripts installed automatically on pip install
- **`pyproject.toml` fixed** — proper `setuptools.build_meta` backend; package builds and passes `twine check`
- **GitHub Actions** — `.github/workflows/publish-pypi.yml` + `publish-testpypi.yml` with OIDC trusted publishing
- **PyPI-ready** — `dist/mikrotikapi_bf-3.6.0-py3-none-any.whl` built and validated

### v3.5.3
- **5 Nmap NSE scripts** in `nse/`: `mikrotik-routeros-version`, `mikrotik-api-brute`, `mikrotik-default-creds`, `mikrotik-api-info`, `mikrotik-winbox-cve-2018-14847`
- **pip install support** — `pyproject.toml` + `mikrotikapi_bf/` entry point package
- **`mikrotikapi-bf --nse-path`** — prints installed NSE scripts directory for Nmap

### v3.5.2
- **`version.py`** — single source of truth for version (all modules import from here)
- **`.env.example`** — safe template committed; `.env` stays in `.gitignore`
- **`python-dotenv`** — `.env` loaded automatically at startup

### v3.5.1
- Fix: syntax error in CVE-2025-6563 XSS payload
- Credits & Acknowledgements section (13 contributors)
- Comprehensive wiki guides en-US + pt-BR (40+ CLI flags documented)

### v3.5.0
- `modules/decoder.py` — Python 3 port of [mikrotik-tools](https://github.com/0ki/mikrotik-tools): `UserDatDecoder`, `BackupDecoder`, `SupoutDecoder`, `MTDatDecoder`
- `xpl/npk_decoder.py` — NPK package analyzer (18 part types)
- `--target-list / -T` — multi-target scanning from file
- `--decode-userdat`, `--decode-backup`, `--analyze-npk`, `--decode-supout`
- 5 new CVEs: CVE-2019-3981, CVE-2020-5720, CVE-2022-45313, CVE-2017-20149, CVE-2025-6563
- **Total: 40 exploit classes** | Lab validation on RouterOS 7.20.7 — 8 vulnerabilities confirmed

### v3.4.0
- 13 Exploit-DB public PoC exploits (full EDB Mikrotik list coverage)
- Complete CVE/EDB coverage table in README

### v3.3.0
- MAC-Server / Layer-2: MNDP discovery, MAC-Telnet brute, CVE-2018-14847-MAC
- 5 new CVE exploit classes
- Attack surface diagrams (3 images)

---

## 🙏 Credits & Acknowledgements

| Contributor | Contribution | Link |
|-------------|-------------|------|
| **Federico Massa & Ramiro Caire** | MKBRUTUS — original RouterOS API brute-force concept | [mkbrutusproject/MKBRUTUS](https://github.com/mkbrutusproject/MKBRUTUS) |
| **Kirils Solovjovs** (@KirilsSolovjovs) | mikrotik-tools: user.dat decoder, backup decoder, NPK format research — ported to Python 3 | [0ki/mikrotik-tools](https://github.com/0ki/mikrotik-tools) |
| **Dmitriusan** | Empty `read_sentence()` fix + socket timeout retry (issue #3) | [Dmitriusan/MikrotikAPI-BF](https://github.com/Dmitriusan/MikrotikAPI-BF) |
| **alina0x** | Multi-target scanning via `ips.txt` → `--target-list / -T` | [alina0x/mikrotik-multithread-bf](https://github.com/alina0x/mikrotik-multithread-bf) |
| **rafathasan** | Autosave + session resume improvements | [rafathasan/MikrotikAPI-BF-Improved](https://github.com/rafathasan/MikrotikAPI-BF-Improved) |
| **sajadmirave** | Connection check before brute-force (PR #4) | [sajadmirave/MikrotikAPI-BF](https://github.com/sajadmirave/MikrotikAPI-BF) |
| **BasuCert** | WinboxPoC / MACServerExploit.py — MAC-server attack reference | [BasuCert/WinboxPoC](https://github.com/BasuCert/WinboxPoC) |
| **Jacob Baines** (Tenable) | CVE-2019-3924, CVE-2019-3943, CVE-2019-3976/3977/3978 | [tenable/routeros](https://github.com/tenable/routeros) |
| **BigNerd95 / Lorenzo Santina** | Chimay-Red Stack Clash PoC (EDB-44283/44284) | [BigNerd95/Chimay-Red](https://github.com/BigNerd95/Chimay-Red) |
| **ShadOS** | SNMP DoS + SNMP write PoC (EDB-31102, EDB-6366) | Exploit-DB |
| **FarazPajohan** | FTP/ICMP/ARP/RouterBoard DoS PoCs | Exploit-DB |
| **kingcope** | ROSSSH sshd heap corruption (EDB-28056) | Exploit-DB |
| **xis_one** | Syslog Server BoF DoS Metasploit module (EDB-24968) | Exploit-DB |
| **hyp3rlinx** | DNSmasq/Mikrotik SQL Injection (EDB-39817) | Exploit-DB |
| **Prak Sokchea** | RouterOS 7.19.1 WebFig XSS (EDB-52366) | Exploit-DB |
| **0xjpuff** | CVE-2023-30799 (FOISted) PoC reference | [0xjpuff/CVE-2023-30799](https://github.com/0xjpuff/CVE-2023-30799) |

*RouterOS ecosystem diagram adapted from Kirils Solovjovs' research — Balccon 2017.*

---

## ⚠️ Legal Notice

<!-- LEGAL-NOTICE-UG-MRH -->

- **Use** — For education, research, and **explicitly authorized** security testing only. Do not use against systems without formal written permission.
- **No warranty** — Provided **AS IS** under [MIT License](LICENSE). No fitness guarantees.
- **No liability** — Author(s) not liable for misuse, damages, or third-party claims. **Use at your own risk.**
- **Attribution** — Keep copyright notices. Pull requests and issues are welcome.

---

## 💬 Support

- **GitHub:** [https://github.com/mrhenrike/MikrotikAPI-BF](https://github.com/mrhenrike/MikrotikAPI-BF)
- **Issues:** [https://github.com/mrhenrike/MikrotikAPI-BF/issues](https://github.com/mrhenrike/MikrotikAPI-BF/issues)
- **Wiki:** [https://github.com/mrhenrike/MikrotikAPI-BF/wiki](https://github.com/mrhenrike/MikrotikAPI-BF/wiki)
- **Security reports:** See [SECURITY.md](SECURITY.md)

Licensed under MIT — see [`LICENSE`](LICENSE).


