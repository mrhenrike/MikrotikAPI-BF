# Security Policy

## Author & Maintainer

**André Henrique** ([@mrhenrike](https://github.com/mrhenrike))  
LinkedIn / X: @mrhenrike

---

## Supported Versions

Only the **latest stable release** receives security fixes.
Older releases are unsupported — upgrade to the current version.

| Version | Status | Security fixes |
| ------- | ------ | -------------- |
| **3.5.x** (current) | :white_check_mark: Active | Yes |
| 3.4.x | :x: EOL | No — upgrade to 3.5.x |
| 3.3.x and below | :x: EOL | No — upgrade to 3.5.x |

---

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

### Option 1 — GitHub Private Vulnerability Reporting (preferred)

Use the **[Report a vulnerability](https://github.com/mrhenrike/MikrotikAPI-BF/security/advisories/new)** button on the Security tab.  
This creates a private advisory visible only to the maintainer.

### Option 2 — CERT/CC VINCE

For vulnerabilities with broader scope (affecting RouterOS itself), you may
coordinate via the **CERT/CC VINCE** platform:

- Portal: https://kb.cert.org/vince/
- Active case for RouterOS API: VUID 375660 (brute-force / rate-limiting)

### Option 3 — Direct contact

Email or social DM via the channels listed on the maintainer's GitHub profile.

---

## What to Include

Please provide:

1. **Version** — output of python mikrotikapi-bf.py --version
2. **Description** — clear description of the vulnerability
3. **Steps to reproduce** — minimal PoC or command sequence
4. **Impact** — what an attacker could achieve
5. **Environment** — OS, Python version, RouterOS version if applicable
6. **Fix proposal** (optional)

---

## Response Timeline

| Stage | Target time |
|-------|-------------|
| Acknowledgement | ≤ 48 hours |
| Initial assessment | ≤ 7 days |
| Patch / advisory | ≤ 30 days (critical) / 90 days (others) |
| Public disclosure | After patch is available |

---

## Scope

This security policy covers **mrhenrike/MikrotikAPI-BF** only.  
For vulnerabilities in **MikroTik RouterOS itself**, report directly to MikroTik:
- https://mikrotik.com/supportsec
- https://blog.mikrotik.com/security/

---

## Legal

Use MikrotikAPI-BF only on systems you own or have **explicit written authorization** to test.  
Unauthorized use is prohibited and may be illegal. See [LICENSE](LICENSE).