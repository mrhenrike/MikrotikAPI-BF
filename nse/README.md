# MikrotikAPI-BF — Nmap NSE Scripts

Nmap Scripting Engine (NSE) scripts for MikroTik RouterOS security assessment.  
Complement the main Python tool with Nmap-native scanning capabilities.

---

## Installation

### Method 1 — pip (recommended)

```bash
pip install mikrotikapi-bf
# NSE scripts are installed automatically
mikrotikapi-bf --nse-path   # prints the NSE scripts directory
```

### Method 2 — Manual copy

```bash
# Linux/macOS
cp nse/*.nse /usr/share/nmap/scripts/
nmap --script-updatedb

# Windows
copy nse\*.nse "C:\Program Files (x86)\Nmap\scripts\"
nmap --script-updatedb
```

### Method 3 — Direct path

```bash
nmap --script ./nse/mikrotik-routeros-version.nse <target>
```

---

## Scripts

| Script | Ports | Category | Description |
|--------|-------|----------|-------------|
| `mikrotik-routeros-version.nse` | 80,443,888,8291,8728,8729 | discovery | Fingerprint RouterOS version from multiple vectors |
| `mikrotik-api-brute.nse` | 8728,8729 | brute | Brute-force RouterOS API credentials |
| `mikrotik-default-creds.nse` | 8728,8729,80,443 | auth | Test default/empty credentials on all interfaces |
| `mikrotik-api-info.nse` | 8728,8729 | discovery | Authenticated info dump (users, services, firewall) |
| `mikrotik-winbox-cve-2018-14847.nse` | 8291 | vuln | Check for Winbox credential disclosure (Chimay-Red) |

---

## Usage Examples

```bash
# Full discovery scan (all MikroTik scripts)
nmap -p 80,443,8291,8728,8729 \
  --script "mikrotik-*" \
  -sV 192.168.1.0/24

# Version fingerprint only (safe, no auth)
nmap -p 80,8291,8728 --script mikrotik-routeros-version <target>

# Check for CVE-2018-14847 (Winbox credential disclosure)
nmap -p 8291 --script mikrotik-winbox-cve-2018-14847 <target>

# Brute-force API with wordlists
nmap -p 8728 --script mikrotik-api-brute \
  --script-args userdb=users.lst,passdb=passwords.lst \
  <target>

# Quick default credential check
nmap -p 8728,80 --script mikrotik-default-creds <target>

# Authenticated info dump (after finding creds)
nmap -p 8728 --script mikrotik-api-info \
  --script-args mikrotik-api-info.user=admin,mikrotik-api-info.pass=C0C0D3GR120 \
  <target>

# Full vulnerability assessment (combine with Python tool)
nmap -p 8728 --script mikrotik-routeros-version,mikrotik-default-creds <target>
python mikrotikapi-bf.py -t <target> --scan-cve -U admin -P <found_pass>
```

---

## CVE Coverage via NSE

| Script | CVE |
|--------|-----|
| `mikrotik-winbox-cve-2018-14847.nse` | CVE-2018-14847 (CRITICAL 9.1) |
| `mikrotik-routeros-version.nse` | Version mapping to all applicable CVEs |
| `mikrotik-api-brute.nse` | VUID 375660 — no rate-limiting (TCP/8728) |
| `mikrotik-default-creds.nse` | VUID 375660 — default credentials |

---

## References

- [MikrotikAPI-BF Python Tool](https://github.com/mrhenrike/MikrotikAPI-BF)
- [Nmap NSE Documentation](https://nmap.org/book/nse.html)
- [RouterOS API Manual](https://wiki.mikrotik.com/wiki/Manual:API)
- [CVE-2018-14847](https://nvd.nist.gov/vuln/detail/CVE-2018-14847)
- [CERT/CC VINCE VUID 375660](https://kb.cert.org/vince/)
