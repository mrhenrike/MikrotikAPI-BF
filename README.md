# 🔐 MikrotikAPI-BF v2.1

[![Python Version](https://img.shields.io/badge/python-3.8%20%7C%203.9%20%7C%203.10%20%7C%203.11%20%7C%203.12-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1-red.svg)](docs/CHANGELOG.md)
[![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey.svg)](README.md)

Advanced CLI toolkit for security testing of Mikrotik RouterOS and CHR. It performs credential testing against multiple entry points (RouterOS API/REST-API) with optional post-login validation on network services (FTP/SSH/Telnet), includes robust session persistence, progress/ETA, export, stealth, and fingerprinting.

## ✨ Key Features

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
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -U admin -P 123456

# With wordlists (provide your own, not tracked in repo)
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u wordlists/users.lst -p wordlists/passwords.lst

# With post-login validation
python mikrotikapi-bf-v2.1.py -t 192.168.1.1 -u users.lst -p passwords.lst --validate ftp,ssh,telnet

# Full pentest-style run
python mikrotikapi-bf-v2.1.py \
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
python mikrotikapi-bf-v2.1.py --help
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

## 🗺️ Where This Tool Attacks (Attack Surface Mapping)

Referencing the Mikrotik ecosystem map from the community project [`0ki/mikrotik-tools`](https://github.com/0ki/mikrotik-tools) — image: `mikrotik_eco.png` ([link](https://github.com/0ki/mikrotik-tools/raw/master/mikrotik_eco.png)). Our tool focuses on:

- Access vectors: `telnet`, `ssh`, `ftp`, `web` (REST endpoints) and `api`;
- Access targets: the services and daemons bound to the device CPU/stack, not internal storage or removable media.

Why it’s possible:
- These services expose interactive authentication endpoints reachable over the network.
- RouterOS supports API/REST for automation; FTP/SSH/Telnet are often enabled for management or legacy reasons.

How to reduce or eliminate exposure:
- Disable unused services (e.g., `telnet`, `ftp`).
- Restrict `api`, `ssh`, and `http/https` to management networks only.
- Enforce strong passwords and multi-factor where possible (e.g., SSH keys).
- Apply per-service `address-list` filters and firewall rules.
- Enable rate limits, lockouts, and schedule maintenance windows.
- Keep RouterOS updated, review logs, and rotate credentials.

## 📄 CLI Essentials

Common flags:
- `--validate ftp,ssh,telnet` — post-login validation with optional custom ports (`ssh=2222`).
- `--resume | --force | --list-sessions | --session-info` — session control.
- `--stealth` — stealth delays and header rotation.
- `--progress` — progress bar with ETA.
- `--export json,csv,xml,txt | --export-all` — reporting.

## 📁 Project Layout

```
MikrotikAPI-BF/
├── mikrotikapi-bf-v2.1.py
├── _api.py  _log.py  _session.py  _export.py  _progress.py  _stealth.py  _fingerprint.py  _wordlists.py
├── docs/
│   ├── README.md  API_REFERENCE.md  INSTALLATION.md  USAGE_EXAMPLES.md  index.html  CHANGELOG.md  FEATURES.md  QUICKSTART.md  VERBOSE_GUIDE.md
├── requirements.txt  install-v2.1.sh
└── .gitignore
```

## ⚠️ Legal Notice and Responsible Use
- Use only on systems you own or have explicit, written authorization to test.
- Your tests will likely be logged; coordinate with stakeholders.
- Respect rate limits, user privacy, and applicable laws.

## 🔧 Troubleshooting (Quick)
- Python 3.13+ may deprecate stdlib modules (e.g., `telnetlib`); prefer 3.12.x.
- For connection timeouts: check routing, firewall, and service ports.
- For REST-API TLS issues: use `--ssl` and confirm certificates where appropriate.

## 📚 Documentation
- [Full Documentation](docs/README.md)
- [API Reference](docs/API_REFERENCE.md)
- [Installation Guide](docs/INSTALLATION.md)
- [Usage Examples](docs/USAGE_EXAMPLES.md)
- [HTML Docs](docs/index.html)

## 🆕 What’s New in v2.1
- Persistent sessions (resume, ETA, duplicate avoidance)
- Stealth mode (Fibonacci delays, UA rotation)
- Advanced fingerprinting
- Post-login validation for FTP/SSH/Telnet
- Multi-format export and improved progress UI
- Removed unreliable Winbox/WebFig testing

## Support
- GitHub: https://github.com/mrhenrike/MikrotikAPI-BF
- Issues: https://github.com/mrhenrike/MikrotikAPI-BF/issues

Licensed under MIT. See `LICENSE`.