# MikrotikAPI-BF v3.3.0

[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-3.3.0-red.svg)](docs/CHANGELOG.md)
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

Understanding where MikrotikAPI-BF operates within the Mikrotik ecosystem is crucial for effective security testing. The following diagram illustrates the complete attack surface of Mikrotik RouterOS devices:

<div align="center">

![Mikrotik Ecosystem Attack Surface](img/mikrotik_eco.png)

*Mikrotik RouterOS Ecosystem Map - Attack Surface Visualization*

</div>

### 🎯 **Our Tool's Focus Areas**

**Access Vectors (Orange boxes in diagram):**
- **`api`** - RouterOS API (TCP 8728) - Binary protocol for automation
- **`web`** - REST-API endpoints (TCP 80/443) - HTTP/HTTPS with Basic Auth
- **`ssh`** - Secure Shell (TCP 22) - Encrypted remote access
- **`telnet`** - Unencrypted remote access (TCP 23) - Legacy protocol
- **`ftp`** - File Transfer Protocol (TCP 21) - File management

**Access Targets (Blue boxes in diagram):**
- Network services and daemons bound to the CPU
- Management interfaces and authentication systems
- **NOT** internal storage or removable media (those require physical access)

### 🔍 **Why These Attacks Are Possible**

1. **Network Exposure**: These services are intentionally exposed for management and automation
2. **Authentication Endpoints**: Each service provides interactive login capabilities
3. **Legacy Support**: Many services remain enabled for backward compatibility
4. **Automation Requirements**: API/REST endpoints are needed for device management

### 🛡️ **How to Defend Against These Attacks**

**Immediate Actions:**
- **Disable unused services** (telnet, ftp if not needed)
- **Restrict management access** to specific networks using firewall rules
- **Enable strong authentication** (SSH keys, complex passwords)
- **Implement rate limiting** and account lockouts

**Advanced Defenses:**
- **Network segmentation** - Isolate management interfaces
- **VPN access only** - Require VPN connection for management
- **Multi-factor authentication** where supported
- **Regular security updates** and credential rotation
- **Monitoring and logging** - Watch for brute-force attempts

**Modern CHR Defenses:**
- Session controls and request limits
- Per-source rate limiting and temporary lockouts
- Extensive logging of authentication failures
- WAF/IPS protection for HTTP endpoints

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

## What's New in v3.3.0

**MAC-Server / Layer-2 support (new in v3.3.0):**
- `modules/mac_server.py` — MNDP broadcast discovery + MAC-Telnet credential brute-force
- `--mac-discover` flag — finds all Mikrotik devices on the local L2 segment (even without IP)
- `--mac-brute` flag — brute-forces credentials via MAC-Telnet (TCP 20561)
- `--mac-scan-cve` flag — runs CVE-2018-14847 payload against MNDP-discovered devices
- `Exploit_CVE_2018_14847_MAC` — dedicated MAC-based variant of the Winbox credential exploit
- 5 new CVE exploit classes: CVE-2020-20215, CVE-2021-41987, CVE-2023-30800, CVE-2024-2169 + MAC-14847
- CVE database expanded to 22 entries + 2 design-flaw findings

**CVE Coverage (all versions, 22 CVEs):**

| CVE | Title | CVSS | Auth | PoC | Fixed in |
|-----|-------|------|------|-----|----------|
| CVE-2018-7445 | SMB Stack Buffer Overflow (Pre-Auth RCE) | 9.8 | No | Yes | 6.41.4 |
| CVE-2018-10066 | Winbox Auth Bypass / Directory Traversal | 8.1 | No | Yes | 6.42 |
| CVE-2018-14847 | Winbox Credential Disclosure (Chimay-Red) | 9.1 | No | Yes | 6.42.1 |
| CVE-2018-14847-MAC | Winbox Credential Disclosure via MNDP/MAC | 9.1 | No | Yes | 6.42.1 |
| CVE-2019-3924 | WWW Pre-Auth RCE (jsproxy) | 9.8 | No | Yes | 6.43.8 |
| CVE-2019-3943 | HTTP Path Traversal | 8.8 | No | Yes | 6.43.8 |
| CVE-2019-3976 | NPK Arbitrary File Read | 6.5 | Yes | Yes | 6.45.7 |
| CVE-2019-3977 | NPK Arbitrary Code Execution | 7.5 | Yes | Yes | 6.45.7 |
| CVE-2019-3978 | DNS Cache Poisoning | 7.5 | No | Yes | 6.45.7 |
| CVE-2020-20215 | RouterOS MPLS Out-of-Bounds Write (DoS) | 7.5 | No | Yes | 6.47 |
| CVE-2021-27263 | Winbox Auth Bypass (RouterOS 7.0.x) | 7.5 | No | Yes | 7.1 |
| CVE-2021-36522 | www Server Authenticated RCE via Scheduler | 8.8 | Yes | Yes | 6.49.3 |
| CVE-2021-41987 | RADIUS Client Stack Buffer Overflow | 8.1 | No | Yes | 6.49.1 / 7.1 |
| CVE-2022-34960 | Container Feature Privilege Escalation | 8.8 | Yes | Yes | 7.6 |
| CVE-2022-45315 | SMB Authenticated Stack Buffer Overflow | 8.8 | Yes | Yes | 6.49.7 / 7.6 |
| CVE-2023-30799 | Privilege Escalation via supout.rif (FOISted) | 9.1 | Yes | Yes | 6.49.9 / 7.10 |
| CVE-2023-30800 | WWW Service Stack-Based Buffer Overflow (Pre-Auth) | 8.2 | No | Yes | 6.49.9 / 7.10 |
| CVE-2024-27887 | OSPF Route Injection | 7.5 | No | Yes | — |
| CVE-2024-2169 | BFD Protocol Reflection / Amplification Loop | 7.5 | No | Yes | Mitigate |
| CVE-2024-35274 | Authenticated RCE via Scheduler/Script Injection | 8.8 | Yes | Yes | Pending |
| MIKROTIK-CONFIG-001 | WireGuard Private Key Exposure via REST API | — | Yes | Yes | Design |
| MIKROTIK-CONFIG-002 | Packet Sniffer Remote Streaming (Wiretapping) | — | Yes | Yes | Design |

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

## Support
- GitHub: https://github.com/mrhenrike/MikrotikAPI-BF
- Issues: https://github.com/mrhenrike/MikrotikAPI-BF/issues

Licensed under MIT — see [`LICENSE`](LICENSE).
