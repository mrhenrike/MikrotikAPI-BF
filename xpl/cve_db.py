#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
MikroTik RouterOS CVE Database — MikrotikAPI-BF
=================================================
Curated database of publicly disclosed CVEs affecting MikroTik RouterOS,
RouterBoard hardware, and associated services.

Each entry contains:
  cve_id        – Official CVE identifier
  title         – Short descriptive title
  description   – Detailed description of the vulnerability
  severity      – CVSS severity label (CRITICAL / HIGH / MEDIUM / LOW)
  cvss_score    – CVSS v3 base score (float)
  affected      – Affected version ranges as list of tuples (min_major_minor, max_major_minor)
                  Use None for open-ended ranges.
  fixed_in      – First RouterOS version with the fix, or None
  services      – Affected service identifiers (ports/services)
  poc_available – Whether a public PoC or exploit is known
  references    – List of reference URLs
  exploit_type  – Type of exploit (rce, disclosure, traversal, dos, priv_esc, auth_bypass)
  notes         – Optional additional context
"""

from typing import Dict, List, Optional, Tuple


# Each CVE entry is a dict; version ranges are (major, minor) inclusive tuples
CVE_DATABASE: List[Dict] = [
    # ------------------------------------------------------------------ #
    #  CVE-2018-14847 — Winbox Credential Disclosure (Chimay-Red)         #
    # ------------------------------------------------------------------ #
    {
        "cve_id": "CVE-2018-14847",
        "title": "Winbox Credential Disclosure via Directory Traversal",
        "description": (
            "MikroTik RouterOS through v6.42 allows remote attackers to bypass authentication "
            "and read sensitive files via Winbox (port 8291), disclosing hashed admin credentials "
            "stored in /flash/rw/store/user.dat. First discovered by Vault 7 (CIA leak) and "
            "later popularised as 'Chimay-Red'."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "affected": [(None, (6, 42))],   # all versions up to 6.42 inclusive
        "fixed_in": "6.42.1",
        "services": ["winbox"],
        "poc_available": True,
        "exploit_type": "disclosure",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
            "https://www.exploit-db.com/exploits/45220",
            "https://github.com/BasuCert/WinboxPoC",
        ],
        "notes": "Works even when Winbox service is enabled with default configuration.",
    },
    # ------------------------------------------------------------------ #
    #  CVE-2019-3943 — RouterOS Path Traversal                            #
    # ------------------------------------------------------------------ #
    {
        "cve_id": "CVE-2019-3943",
        "title": "RouterOS HTTP Server Path Traversal",
        "description": (
            "MikroTik RouterOS versions < 6.43.8 and < 6.44 beta 55 are vulnerable to a path "
            "traversal attack via the HTTP server (WebFig). An unauthenticated remote attacker "
            "can read arbitrary files from the device filesystem."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 43))],
        "fixed_in": "6.43.8",
        "services": ["http", "https"],
        "poc_available": True,
        "exploit_type": "traversal",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3943",
            "https://www.exploit-db.com/exploits/46731",
        ],
        "notes": "Combines with CVE-2019-3924 for unauthenticated RCE.",
    },
    # ------------------------------------------------------------------ #
    #  CVE-2019-3924 — RouterOS WWW Server RCE (pre-auth)                  #
    # ------------------------------------------------------------------ #
    {
        "cve_id": "CVE-2019-3924",
        "title": "RouterOS WWW Server Pre-Auth RCE",
        "description": (
            "MikroTik RouterOS versions < 6.43.12 allow remote attackers to execute arbitrary "
            "code as root via the www server (port 80) without authentication. "
            "Chained with CVE-2019-3943 for filesystem access."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected": [(None, (6, 43))],
        "fixed_in": "6.43.12",
        "services": ["http", "https"],
        "poc_available": True,
        "exploit_type": "rce",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3924",
            "https://www.exploit-db.com/exploits/46842",
        ],
        "notes": "Metasploit module: exploit/linux/http/mikrotik_www_exec",
    },
    # ------------------------------------------------------------------ #
    #  CVE-2020-20213 — RouterOS Denial of Service via NPK                 #
    # ------------------------------------------------------------------ #
    {
        "cve_id": "CVE-2020-20213",
        "title": "RouterOS NPK Package Denial of Service",
        "description": (
            "MikroTik RouterOS v6.44.6 — v6.47.9 and v7.0.x allow an attacker with local or "
            "Winbox access to craft a malicious NPK upgrade package that triggers a kernel panic, "
            "resulting in a denial of service."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((6, 44), (6, 47)), ((7, 0), (7, 0))],
        "fixed_in": "6.47.10",
        "services": ["winbox"],
        "poc_available": False,
        "exploit_type": "dos",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-20213",
        ],
        "notes": "Requires valid Winbox credentials.",
    },
    # ------------------------------------------------------------------ #
    #  CVE-2021-27263 — Winbox Authentication Bypass                       #
    # ------------------------------------------------------------------ #
    {
        "cve_id": "CVE-2021-27263",
        "title": "Winbox Authentication Bypass",
        "description": (
            "A logic flaw in Winbox (port 8291) authentication in MikroTik RouterOS v6.x and v7.x "
            "before 7.1 allows remote attackers to bypass authentication under certain race conditions."
        ),
        "severity": "HIGH",
        "cvss_score": 8.1,
        "affected": [(None, (6, 99)), ((7, 0), (7, 0))],
        "fixed_in": "7.1",
        "services": ["winbox"],
        "poc_available": True,
        "exploit_type": "auth_bypass",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-27263",
        ],
        "notes": "Patched in RouterOS 7.1; v6 branch not fully addressed.",
    },
    # ------------------------------------------------------------------ #
    #  CVE-2022-45315 — SMB Service Buffer Overflow                        #
    # ------------------------------------------------------------------ #
    {
        "cve_id": "CVE-2022-45315",
        "title": "RouterOS SMB Service Stack Buffer Overflow (RCE)",
        "description": (
            "A stack-based buffer overflow in the RouterOS SMB service (smb.exe) allows an "
            "authenticated remote attacker to execute arbitrary code with root privileges. "
            "Affects RouterOS v6.x before 6.49.7 and v7.x before 7.6."
        ),
        "severity": "HIGH",
        "cvss_score": 8.8,
        "affected": [(None, (6, 49)), ((7, 0), (7, 5))],
        "fixed_in": "6.49.7",
        "services": ["smb"],
        "poc_available": True,
        "exploit_type": "rce",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-45315",
            "https://github.com/cq674350529/pocs/tree/master/routeros",
        ],
        "notes": "Requires authenticated access; SMB not enabled by default.",
    },
    # ------------------------------------------------------------------ #
    #  CVE-2023-30799 — Privilege Escalation via supout.rif                #
    # ------------------------------------------------------------------ #
    {
        "cve_id": "CVE-2023-30799",
        "title": "RouterOS Privilege Escalation via supout.rif",
        "description": (
            "MikroTik RouterOS versions before 6.49.8 (stable) and before 7.10 (long-term) "
            "are vulnerable to a privilege escalation attack via the diagnostic support output "
            "file (supout.rif). An attacker with admin (non-Jailed) access can escalate to the "
            "'super-admin' role, gaining full /nova/ filesystem access."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "affected": [(None, (6, 49)), ((7, 0), (7, 9))],
        "fixed_in": "6.49.8",
        "services": ["winbox", "api", "http"],
        "poc_available": True,
        "exploit_type": "priv_esc",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-30799",
            "https://vulncheck.com/blog/mikrotik-foisted-revisited",
            "https://github.com/0xjpuff/CVE-2023-30799",
        ],
        "notes": "FOISted attack – requires admin credentials; super-admin has jailbreak access.",
    },
    # ------------------------------------------------------------------ #
    #  CVE-2023-32154 — RouterOS IPv6 DHCPv6 RCE                          #
    # ------------------------------------------------------------------ #
    {
        "cve_id": "CVE-2023-32154",
        "title": "RouterOS IPv6 DHCPv6 Remote Code Execution",
        "description": (
            "MikroTik RouterOS v6.x and v7.x process malformed DHCPv6 packets in a way that "
            "allows remote unauthenticated attackers on the same network to execute arbitrary code "
            "via a specially crafted DHCPv6 message."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected": [(None, (6, 49)), ((7, 0), (7, 9))],
        "fixed_in": "7.9.1",
        "services": ["dhcpv6"],
        "poc_available": False,
        "exploit_type": "rce",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-32154",
        ],
        "notes": "Requires IPv6 DHCPv6 service to be enabled and attacker on local network.",
    },
    # ------------------------------------------------------------------ #
    #  CVE-2024-27887 — RouterOS OSPF Route Injection                      #
    # ------------------------------------------------------------------ #
    {
        "cve_id": "CVE-2024-27887",
        "title": "RouterOS OSPF Route Injection",
        "description": (
            "MikroTik RouterOS before 7.14 allows an adjacent attacker to inject arbitrary OSPF "
            "routes without authentication, leading to traffic interception or denial of service."
        ),
        "severity": "HIGH",
        "cvss_score": 8.1,
        "affected": [((7, 0), (7, 13))],
        "fixed_in": "7.14",
        "services": ["ospf"],
        "poc_available": False,
        "exploit_type": "dos",
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-27887",
        ],
        "notes": "OSPF must be configured on the router.",
    },
]


def _parse_version(version_str: str) -> Optional[Tuple[int, int]]:
    """Parse a version string like '6.49.3' into (6, 49)."""
    if not version_str:
        return None
    try:
        parts = version_str.split(".")
        return (int(parts[0]), int(parts[1]))
    except (IndexError, ValueError):
        return None


def get_cves_for_version(version: str) -> List[Dict]:
    """
    Return CVEs applicable to a given RouterOS version string.

    Args:
        version: RouterOS version string, e.g. ``"6.48.6"`` or ``"7.5"``.

    Returns:
        Filtered list of CVE dicts from CVE_DATABASE.
    """
    parsed = _parse_version(version)
    if not parsed:
        return list(CVE_DATABASE)  # return all if we can't parse

    maj, minor = parsed
    applicable: List[Dict] = []

    for cve in CVE_DATABASE:
        for rng in cve.get("affected", []):
            low, high = rng
            # Check lower bound
            if low is not None:
                low_maj, low_min = low
                if (maj, minor) < (low_maj, low_min):
                    continue
            # Check upper bound
            if high is not None:
                hi_maj, hi_min = high
                if (maj, minor) > (hi_maj, hi_min):
                    continue
            applicable.append(cve)
            break  # matched at least one range

    return applicable


def get_all_cves() -> List[Dict]:
    """Return the complete CVE database."""
    return list(CVE_DATABASE)
