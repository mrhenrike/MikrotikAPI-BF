# MikrotikAPI-BF v3.4.0

[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.4.0-red.svg)](docs/CHANGELOG.md)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](README.md)
[![Wiki](https://img.shields.io/badge/Wiki-GitHub-orange)](https://github.com/mrhenrike/MikrotikAPI-BF/wiki)

Advanced CLI toolkit for security testing of Mikrotik RouterOS and CHR. It performs credential testing against multiple entry points (RouterOS API/REST-API) with optional post-login validation on network services (FTP/SSH/Telnet), includes robust session persistence, progress/ETA, export, stealth, fingerprinting, and — since v3.3.0 — Layer-2 MAC-Server discovery/brute and an expanded CVE exploit coverage.

**Portuguese (pt-BR):** [README.pt-BR.md](README.pt-BR.md) · **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md) · **Code of Conduct:** [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

## ✨ Key Features

### 🌐 MAC-Server / Layer-2 Discovery (v3.3.0+)
- **MNDP broadcast** (UDP 20561) — discovers all Mikrotik devices on the local L2 segment, including those with no IP assigned
- **MAC-Telnet brute-force** (TCP 20561) — tests credentials against discovered devices using Mikrotik's proprietary MAC-Telnet protocol
- **CVE-2018-14847-MAC** exploit — runs Winbox credential disclosure against MNDP-discovered devices
- **Layer-2 only**: these features require the attacker to be on the same VLAN/switch as the targets

### 🔐 Authentication Targets
- **RouterOS API** (TCP 8728) — proprietary binary protocol
- **REST-API** over **HTTP/HTTPS** (TCP 80/443) — Basic Auth
- Full TLS support for HTTPS

### 🛡️ Post-Login Service Validation
- **FTP** (TCP 21)
- **SSH** (TCP 22)
- **Telnet** (TCP 23)
- Custom ports supported per service (e.g., `--validate ssh=2222`)

### 🔄 Persistent Sessions
- Resume from the last attempt, JtR-like behavior
- Duplicate test avoidance for the same target/services/wordlist
- ETA calculation based on average attempt time
- Session listing and inspection

### 🥷 Stealth Mode
- Fibonacci-based randomized delays
- User-Agent rotation and randomized headers
- Jitter to avoid timing signatures

### 🔍 Fingerprinting
- RouterOS version, device model, open ports, services
- Basic risk scoring and observations for exposure

### 📊 Progress & Export
- Deterministic progress bar with ETA and speed
- Export in JSON, CSV, XML and TXT

### 🎯 Smart Wordlists
- Target-informed combinations, BR-focused lists supported locally by the user

## 🚀 Quick Start

### Prerequisites
- Python 3.8–3.12 (3.12.x recommended)
- Windows, Linux, or macOS

### One-liners
```bash
# Basic
python mikrotikapi-bf.py -t 192.168.1.1 -U admin -P 123456

# With wordlists (provide your own, not tracked in repo)
python mikrotikapi-bf.py -t 192.168.1.1 -u wordlists/users.lst -p wordlists/passwords.lst

# With post-login validation
python mikrotikapi-bf.py -t 192.168.1.1 -u users.lst -p passwords.lst --validate ftp,ssh,telnet

# Full pentest-style run
python mikrotikapi-bf.py \
  -t 192.168.1.1 \
  -u wordlists/users.lst \
  -p wordlists/passwords.lst \
  --validate ftp,ssh,telnet \
  --stealth --fingerprint --progress --export-all \
  --threads 5 -vv
```

### Installation
```bash
git clone https://github.com/mrhenrike/MikrotikAPI-BF.git
cd MikrotikAPI-BF
pip install -r requirements.txt
python mikrotikapi-bf.py --help
```

## 🧭 Services Tested and Why Winbox/WebFig Are Not

### Supported services (tested correctly)
- API (8728) — binary login via `_api.py`
- REST-API (80/443) — HTTP Basic Auth against `/rest/system/identity`
- FTP/SSH/Telnet — functional post-login validation using standard clients

### Not supported (and why)
- **Winbox** (TCP 8291): proprietary GUI protocol; there is no reliable, legal, and portable Linux/Python library to emulate the Winbox login handshake. Previous attempts typically degenerate into port-open checks, producing false positives — therefore intentionally removed.
- **Web Console (WebFig)**: on target CHR builds it frequently responds `406 Not Acceptable` for automated requests and/or requires dynamic flows not stable for programmatic auth. This produces false positives/negatives; therefore removed to avoid misleading results.

## 🧱 Modern CHR Defenses You Will Hit
- Session controls and server-side antifraud for auth flows
- Request limits and rate-limiting per source
- Temporary account lockouts and backoff windows
- Extensive logging (auth failures, rate limiting, HTTP 4xx/5xx)
- IDS/IPS/NAC and WAF-likes in front of HTTP endpoints

You should expect throttling and evidence in logs during testing. Prefer stealth mode, sensible thread counts, and authorized maintenance windows.

## 🗺️ Attack Surface Mapping

Understanding where MikrotikAPI-BF operates within the Mikrotik RouterOS ecosystem. The diagrams below show the full attack surface, coverage status per vector, and per target.

### Full Attack Surface — Coverage Status (v3.4.0)

<div align="center">

![MikrotikAPI-BF Full Attack Surface Map](img/mikrotik_full_attack_surface.png)

*Complete RouterOS attack surface with MikrotikAPI-BF coverage indicators (✓ covered / ✗ not yet covered)*

</div>

---

### 🟠 Access Vectors — Coverage Detail

<div align="center">

![Access Vectors Coverage](img/mikrotik_access_vectors.png)

*Orange boxes = Access Vectors. Green ✓ = tool covers this vector. Red ✗ = not yet covered.*

</div>

| Access Vector | Port(s) | Tool Coverage | How |
|--------------|---------|--------------|-----|
| **telnet** | TCP/23 | ✅ Covered | Post-login validation (`--validate telnet`) |
| **ssh** | TCP/22 | ✅ Covered | Post-login validation + EDB-28056 (ROSSSH heap) |
| **web** (WebFig/REST) | TCP/80, 443 | ✅ Covered | REST API brute-force + 10+ CVE/EDB exploits |
| **winbox** | TCP/8291 | ✅ Covered | CVE-2018-14847, CVE-2018-10066, CVE-2021-27263 |
| **ftp** | TCP/21 | ✅ Covered | Post-login validation + CVE-2019-3976/3977 + EDB-44450 |
| **samba** (SMB) | TCP/445 | ✅ Covered | CVE-2018-7445, CVE-2022-45315 |
| **mactel** (MAC-Telnet) | TCP/20561 | ✅ Covered | `modules/mac_server.py` — v3.3.0+ MNDP + brute |
| **dude** | TCP/2210 | ❌ Not covered | The Dude monitoring client — no PoC implemented |
| **setup** (Netinstall) | UDP/5000 | ❌ Not covered | Netinstall / Flashfig boot — physical/LAN access |
| **netboot** | TFTP/69 | ❌ Not covered | Network boot vector — physical LAN requirement |
| **btest** | TCP/2000 | ❌ Not covered | Bandwidth Test server — protocol not implemented |
| **dhcp** | UDP/67-68 | ❌ Not covered | DHCP server attack surface — out of current scope |
| **console** | RS-232 | ❌ Not covered | Physical serial console — requires physical access |
| **Woobm-USB** | USB | ❌ Not covered | USB-based recovery — requires physical access |

**Coverage: 7 / 14 Access Vectors (50%) — network-accessible vectors fully covered**

---

### 🔵 Access Targets — Coverage Detail

<div align="center">

![Access Targets Coverage](img/mikrotik_access_targets.png)

*Blue/cyan boxes = Access Targets. Green ✓ = covered. Red ✗ = not yet covered.*

</div>

| Access Target | Component | Coverage | CVEs / Notes |
|--------------|-----------|---------|--------------|
| **filesystem** | `/flash/rw/store/` | ⚠️ Partial | CVE-2018-14847 reads `user.dat`; CVE-2019-3943 path traversal |
| **supout.rif** | Diagnostic file | ✅ Covered | CVE-2023-30799 (FOISted) — priv escalation via supout upload |
| **.npk** | Package files | ✅ Covered | CVE-2019-3977/3976 — arbitrary exec/read via NPK |
| **.backup** | Config backup | ❌ Not covered | No exploit for backup file extraction/abuse |
| **FLASH** | Internal flash | ❌ Not covered | Requires direct physical or filesystem access |
| **NAND** | NAND storage | ❌ Not covered | Low-level, requires physical access |
| **HDD** | Hard disk (CHR) | ❌ Not covered | CHR-specific — no direct exploit path yet |
| **kvm** | Virtual machine | ❌ Not covered | KVM hypervisor attack — no PoC in scope |

---

### 🔍 Why These Attacks Are Possible

1. **Network Exposure** — Management services intentionally exposed (API, REST, Winbox, Telnet)
2. **No Rate-Limiting** — RouterOS API (TCP 8728/8729) has no built-in brute-force protection (VUID 375660)
3. **Legacy Protocol Support** — Telnet, FTP, SMBv1 remain enabled for backward compatibility
4. **Filesystem Access** — Pre-auth file reads (CVE-2018-14847) expose credential databases
5. **Layer-2 Exposure** — MAC-Server/MNDP reveals devices with no IP assignment

### 🛡️ Defensive Mitigations

**Immediate Actions:**
- Disable unused services: `/ip service disable telnet,ftp,api`
- Restrict access by IP: `/ip service set api address=10.0.0.0/8`
- Change default API port and enable TLS (`api-ssl`)
- Enable strong authentication (SSH keys, complex passwords ≥ 20 chars)
- Disable MAC-Server: `/tool mac-server set allowed-interface-list=none`

**Advanced Defenses:**
- Rate-limit firewall rules on management ports
- VPN-only management access
- Disable Winbox if REST API suffices (or restrict to mgmt VLAN)
- Monitor `/log print` for repeated auth failures
- Regular RouterOS updates (subscribe to https://mikrotik.com/download)

**Modern CHR Defenses:**
- Session controls and per-source rate limiting
- Extensive logging of auth failures (`/system logging add topics=info,error`)
- WAF/IPS in front of HTTP management endpoints

## 📄 CLI Essentials

Common flags:
- `--validate ftp,ssh,telnet` — post-login validation with optional custom ports (`ssh=2222`).
- `--resume | --force | --list-sessions | --session-info` — session control.
- `--stealth` — stealth delays and header rotation.
- `--progress` — progress bar with ETA.
- `--export json,csv,xml,txt | --export-all` — reporting.

### MAC-Server (Layer-2) flags (v3.3.0+)
- `--mac-discover` — broadcast MNDP to find Mikrotik devices on the local segment.
- `--mac-brute` — brute-force credentials via MAC-Telnet against discovered devices.
- `--mac-scan-cve` — run CVE-2018-14847-MAC against all MNDP-discovered devices.
- `--mac-iface-ip <IP>` — local IP to bind for MNDP broadcast (default: 0.0.0.0).

```bash
# Layer-2 discovery only
python mikrotikapi-bf.py --mac-discover

# Discover + brute-force via MAC-Telnet
python mikrotikapi-bf.py --mac-discover --mac-brute -d wordlists/combos.lst

# Discover + exploit CVE-2018-14847 via MAC
python mikrotikapi-bf.py --mac-scan-cve
```

> **Layer-2 constraint:** MNDP and MAC-Telnet operate within a single broadcast domain only. They cannot traverse Layer-3 routers. You must be on the same VLAN or switch segment as the targets.

## Project Layout

```
MikrotikAPI-BF/
├── mikrotikapi-bf.py             # Main entry point (v3.3.0)
├── requirements.txt
├── core/                         # Core engine modules
│   ├── api.py                    # RouterOS binary API protocol
│   ├── cli.py                    # CLI argument parsing
│   ├── export.py                 # JSON/CSV/XML/TXT export
│   ├── log.py                    # Logging subsystem
│   ├── progress.py               # Progress bar + ETA
│   ├── retry.py                  # Retry logic with backoff
│   └── session.py                # Persistent session management
├── modules/                      # Feature modules
│   ├── discovery.py              # Network discovery
│   ├── fingerprint.py            # Device fingerprinting
│   ├── mac_server.py             # Layer-2 MNDP discovery + MAC-Telnet brute (v3.3.0)
│   ├── proxy.py                  # Proxy/SOCKS support
│   ├── reports.py                # Report generation
│   ├── stealth.py                # Fibonacci delays + UA rotation
│   └── wordlists.py              # Smart wordlist engine
├── xpl/                          # Exploit/CVE integration
│   ├── cve_db.py                 # CVE database
│   ├── exploits.py               # Exploit dispatcher
│   ├── nvd_shodan.py             # NVD API + Shodan integration
│   └── scanner.py                # Vulnerability scanner
├── docs/
│   ├── README.md  API_REFERENCE.md  INSTALLATION.md  USAGE_EXAMPLES.md
│   ├── CHANGELOG.md  FEATURES.md  QUICKSTART.md  VERBOSE_GUIDE.md  index.html
└── examples/
    ├── example_basic.sh  example_discovery.sh  example_stealth.sh
    ├── example_validation.sh  example_wordlist.sh
    ├── usernames.txt  passwords.txt  combos.txt
```

## ⚠️ Legal Notice and Responsible Use

<!-- LEGAL-NOTICE-UG-MRH -->

- Use only on systems you own or have explicit, written authorization to test.
- Your tests will likely be logged; coordinate with stakeholders.
- Respect rate limits, user privacy, and applicable laws.
- **No warranty** — Provided **AS IS** under [MIT License](LICENSE); no commercial, financial, or fitness guarantees. **No liability** for misuse, damages, or third-party claims — **use at your own risk**.
- **Attribution & contributions** — Keep copyright notices; **pull requests** and **issues** are welcome.

## 🔧 Troubleshooting (Quick)
- Python 3.13+ may deprecate stdlib modules (e.g., `telnetlib`); prefer 3.12.x.
- For connection timeouts: check routing, firewall, and service ports.
- For REST-API TLS issues: use `--ssl` and confirm certificates where appropriate.

## Documentation
- [GitHub Wiki](https://github.com/mrhenrike/MikrotikAPI-BF/wiki) — complete step-by-step guides (en-us + pt-br)
- [Full Documentation](docs/README.md)
- [API Reference](docs/API_REFERENCE.md)
- [Installation Guide](docs/INSTALLATION.md)
- [Usage Examples](docs/USAGE_EXAMPLES.md)
- [HTML Docs](docs/index.html)

## What's New in v3.4.0

**13 new Exploit-DB public PoC exploits (from Exploit-DB Mikrotik entry list):**

| EDB ID | Title | Verified | Type |
|--------|-------|----------|------|
| [EDB-31102](https://www.exploit-db.com/exploits/31102) | RouterOS 3.x SNMP SET DoS | ✓ | Hardware/DoS |
| [EDB-6366](https://www.exploit-db.com/exploits/6366) | RouterOS 3.x SNMP Unauthorized Write | ✓ | Hardware/Remote |
| [EDB-44283](https://www.exploit-db.com/exploits/44283)/[44284](https://www.exploit-db.com/exploits/44284) | Chimay-Red Stack Clash RCE (MIPSBE+x86) | — | Hardware/RCE |
| [EDB-44450](https://www.exploit-db.com/exploits/44450) | FTP Daemon DoS | — | Hardware/DoS |
| [EDB-43317](https://www.exploit-db.com/exploits/43317) | ICMP DoS (6.40.5) | — | Hardware/DoS |
| [EDB-41752](https://www.exploit-db.com/exploits/41752) | RouterBoard DoS (6.38.5) | — | Hardware/DoS |
| [EDB-41601](https://www.exploit-db.com/exploits/41601) | ARP Table Overflow DoS | — | Hardware/DoS |
| [EDB-28056](https://www.exploit-db.com/exploits/28056) | ROSSSH sshd Heap Corruption | — | Hardware/Remote |
| [EDB-24968](https://www.exploit-db.com/exploits/24968) | Syslog Server v1.15 BoF DoS | ✓ | Windows/DoS |
| [EDB-18817](https://www.exploit-db.com/exploits/18817) | Generic Router DoS | — | Hardware/DoS |
| [EDB-52366](https://www.exploit-db.com/exploits/52366) | RouterOS 7.19.1 WebFig XSS | — | Multiple/Remote |
| [EDB-48474](https://www.exploit-db.com/exploits/48474) | Router Monitoring System SQLi | — | WebApp |
| [EDB-39817](https://www.exploit-db.com/exploits/39817) | DNSmasq/Mikrotik SQLi | — | PHP/WebApp |

Total exploit registry: **35 entries** (22 CVEs + 2 design + 13 EDB PoCs).

See [GitHub Wiki — EDB Exploit Coverage](https://github.com/mrhenrike/MikrotikAPI-BF/wiki/EDB-Exploit-Coverage) for full PoC usage guide.

## What's New in v3.3.0

**MAC-Server / Layer-2 support (new in v3.3.0):**
- `modules/mac_server.py` — MNDP broadcast discovery + MAC-Telnet credential brute-force
- `--mac-discover` flag — finds all Mikrotik devices on the local L2 segment (even without IP)
- `--mac-brute` flag — brute-forces credentials via MAC-Telnet (TCP 20561)
- `--mac-scan-cve` flag — runs CVE-2018-14847 payload against MNDP-discovered devices
- `Exploit_CVE_2018_14847_MAC` — dedicated MAC-based variant of the Winbox credential exploit
- 5 new CVE exploit classes: CVE-2020-20215, CVE-2021-41987, CVE-2023-30800, CVE-2024-2169 + MAC-14847
- CVE database expanded to 22 entries + 2 design-flaw findings

**Full Exploit Coverage (35 entries — 22 CVEs + 2 design findings + 13 Exploit-DB PoCs):**

| ID | Title | Auth | EDB | Notes |
|----|-------|------|-----|-------|
| CVE-2018-7445 | SMB Stack Buffer Overflow (Pre-Auth RCE) | No | [44290](https://www.exploit-db.com/exploits/44290) | < 6.41.4 |
| CVE-2018-10066 | Winbox Auth Bypass / Directory Traversal | No | [44813](https://www.exploit-db.com/exploits/44813) | < 6.42 |
| CVE-2018-14847 | Winbox Credential Disclosure (Chimay-Red) | No | [45220](https://www.exploit-db.com/exploits/45220) | < 6.42.1 |
| CVE-2018-14847-MAC | Winbox Credential via MNDP (Layer-2) | No | — | < 6.42.1 |
| CVE-2019-3924 | WWW Firewall/NAT Bypass (jsproxy) | No | [46444](https://www.exploit-db.com/exploits/46444) ✓ | < 6.43.12 |
| CVE-2019-3943 | HTTP Path Traversal | No | [46731](https://www.exploit-db.com/exploits/46731) | < 6.43.8 |
| CVE-2019-3976 | NPK Arbitrary File Read | Yes | — | < 6.45.7 |
| CVE-2019-3977 | NPK Arbitrary Code Execution | Yes | — | < 6.45.7 |
| CVE-2019-3978 | DNS Cache Poisoning | No | [47566](https://www.exploit-db.com/exploits/47566) | < 6.45.7 |
| CVE-2020-20215 | MPLS Out-of-Bounds Write (DoS) | Yes | — | < 6.47 |
| CVE-2021-27263 | Winbox Auth Bypass (RouterOS 7.0.x) | No | — | 7.0.x |
| CVE-2021-36522 | www Authenticated RCE via Scheduler | Yes | — | < 6.49.3 |
| CVE-2021-41987 | RADIUS Client Stack Buffer Overflow | No | — | < 6.49.1 / 7.1 |
| CVE-2022-34960 | Container Feature Privilege Escalation | Yes | — | < 7.6 |
| CVE-2022-45315 | SMB Authenticated Stack Buffer Overflow | Yes | [51451](https://www.exploit-db.com/exploits/51451) | < 6.49.7 |
| CVE-2023-30799 | Privilege Escalation via supout.rif (FOISted) | Yes | — | < 6.49.9 |
| CVE-2023-30800 | WWW Stack-Based Buffer Overflow (Pre-Auth) | No | — | < 6.49.9 |
| CVE-2024-27887 | OSPF Route Injection | No | — | All |
| CVE-2024-2169 | BFD Protocol Reflection / Amplification | No | — | All |
| CVE-2024-35274 | Authenticated RCE via Scheduler Injection | Yes | — | Pending |
| MIKROTIK-CONFIG-001 | WireGuard Private Key Exposure | Yes | — | Design |
| MIKROTIK-CONFIG-002 | Packet Sniffer Remote Streaming | Yes | — | Design |
| **EDB-31102** | RouterOS 3.x SNMP SET Denial of Service | No | [31102](https://www.exploit-db.com/exploits/31102) ✓ | ≤ 3.2 |
| **EDB-6366** | RouterOS 3.x SNMP Unauthorized Write | No | [6366](https://www.exploit-db.com/exploits/6366) ✓ | ≤ 3.13 |
| **EDB-44283/44284** | Chimay-Red Stack Clash RCE (MIPSBE+x86) | No | [44283](https://www.exploit-db.com/exploits/44283)/[44284](https://www.exploit-db.com/exploits/44284) | < 6.38.4 |
| **EDB-44450** | FTP Daemon Denial of Service | No | [44450](https://www.exploit-db.com/exploits/44450) | 6.41.4 |
| **EDB-43317** | ICMP Denial of Service | Yes | [43317](https://www.exploit-db.com/exploits/43317) | 6.40.5 |
| **EDB-41752** | RouterBoard Denial of Service | Yes | [41752](https://www.exploit-db.com/exploits/41752) | 6.38.5 |
| **EDB-41601** | ARP Table Overflow Denial of Service | No | [41601](https://www.exploit-db.com/exploits/41601) | All |
| **EDB-28056** | ROSSSH sshd Remote Heap Corruption | No | [28056](https://www.exploit-db.com/exploits/28056) | Multiple |
| **EDB-24968** | Syslog Server for Windows 1.15 BoF DoS | No | [24968](https://www.exploit-db.com/exploits/24968) ✓ | Win app |
| **EDB-18817** | Generic Router Denial of Service | No | [18817](https://www.exploit-db.com/exploits/18817) | Multiple |
| **EDB-52366** | RouterOS 7.19.1 WebFig Reflected XSS | No | [52366](https://www.exploit-db.com/exploits/52366) | 7.19.1 |
| **EDB-48474** | Router Monitoring System 1.2.3 SQL Injection | No | [48474](https://www.exploit-db.com/exploits/48474) | Web app |
| **EDB-39817** | DNSmasq/Mikrotik Web Interface SQL Injection | No | [39817](https://www.exploit-db.com/exploits/39817) | Web app |

> ✓ = EDB Verified | All PoCs are detection-only; no destructive payloads.

**Previous v3.2.0:**
- Credential matrix workflows, CVE scan export enhancements, WebFig fingerprint context
- Modular architecture: `core/`, `modules/`, `xpl/` packages
- CVE/NVD integration via `xpl/` exploit and scanner modules
- Shodan integration for fingerprinting context
- Proxy/SOCKS5 support via `modules/proxy.py`
- Retry logic with configurable backoff (`core/retry.py`)
- Full persistent sessions (resume, ETA, duplicate avoidance)
- Stealth mode (Fibonacci delays, UA rotation)
- Advanced fingerprinting and risk scoring
- Post-login validation for FTP/SSH/Telnet
- Multi-format export (JSON, CSV, XML, TXT)

## 🙏 Credits & Acknowledgements

This project builds on the work of many in the security research community:

| Contributor | Contribution | Link |
|-------------|-------------|------|
| **Federico Massa & Ramiro Caire** | MKBRUTUS — original RouterOS API brute-force concept | [mkbrutusproject/MKBRUTUS](https://github.com/mkbrutusproject/MKBRUTUS) |
| **Kirils Solovjovs** (@KirilsSolovjovs) | mikrotik-tools: user.dat decoder, backup decoder, NPK format research, supout.rif decoder — all ported to Python 3 in `modules/decoder.py` + `xpl/npk_decoder.py` | [0ki/mikrotik-tools](https://github.com/0ki/mikrotik-tools) |
| **Dmitriusan** | Bug fixes: empty `read_sentence()` list + socket timeout retry (issue #3 — superseded by v3.x architecture) | [Dmitriusan/MikrotikAPI-BF](https://github.com/Dmitriusan/MikrotikAPI-BF) |
| **alina0x** | Multi-target scanning concept via `ips.txt` — implemented as `--target-list / -T` in v3.5.0 | [alina0x/mikrotik-multithread-bf](https://github.com/alina0x/mikrotik-multithread-bf) |
| **rafathasan** | Autosave + session resume improvements — superseded by `--resume` session management | [rafathasan/MikrotikAPI-BF-Improved](https://github.com/rafathasan/MikrotikAPI-BF-Improved) |
| **sajadmirave** | Connection check before brute-force (PR #4) | [sajadmirave/MikrotikAPI-BF](https://github.com/sajadmirave/MikrotikAPI-BF) |
| **BasuCert** | WinboxPoC / MACServerExploit.py — MAC-server attack reference for `CVE-2018-14847-MAC` | [BasuCert/WinboxPoC](https://github.com/BasuCert/WinboxPoC) |
| **Jacob Baines** (Tenable Research) | Tenable RouterOS research — CVE-2019-3924, CVE-2019-3943, CVE-2019-3976/3977/3978 | [tenable/routeros](https://github.com/tenable/routeros) |
| **BigNerd95 / Lorenzo Santina** | Chimay-Red Stack Clash PoC (EDB-44283/44284) | [BigNerd95/Chimay-Red](https://github.com/BigNerd95/Chimay-Red) |
| **ShadOS** | SNMP DoS + SNMP write PoC (EDB-31102, EDB-6366/CVE-2008-6976) | Exploit-DB |
| **FarazPajohan** | FTP/ICMP/ARP/RouterBoard DoS PoCs (EDB-44450, EDB-43317, EDB-41752, EDB-41601) | Exploit-DB |
| **kingcope** | ROSSSH sshd heap corruption (EDB-28056) | Exploit-DB |
| **xis_one** | Syslog Server Windows BoF DoS Metasploit module (EDB-24968) | Exploit-DB |
| **hyp3rlinx** | DNSmasq/Mikrotik SQL Injection (EDB-39817) | Exploit-DB |
| **Prak Sokchea** | RouterOS 7.19.1 WebFig XSS (EDB-52366) | Exploit-DB |
| **0xjpuff** | CVE-2023-30799 (FOISted) PoC reference | [0xjpuff/CVE-2023-30799](https://github.com/0xjpuff/CVE-2023-30799) |

MikroTik RouterOS ecosystem diagram adapted from **Kirils Solovjovs' research** presented at Balccon 2017.

## Support
- GitHub: https://github.com/mrhenrike/MikrotikAPI-BF
- Issues: https://github.com/mrhenrike/MikrotikAPI-BF/issues
- Wiki: https://github.com/mrhenrike/MikrotikAPI-BF/wiki

Licensed under MIT — see [`LICENSE`](LICENSE).
