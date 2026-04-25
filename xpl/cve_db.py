"""MikroTik RouterOS CVE Database — comprehensive curated list.

Includes ALL publicly disclosed MikroTik vulnerabilities with CVSS scores,
affected version ranges, PoC availability, and remediation notes.

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: see version.py (canonical source)
"""
from typing import Dict, List, Optional, Tuple

# Version tuple type: (major, minor, patch)
VersionTuple = Tuple[int, ...]

CVE_DATABASE: List[Dict] = [
    # ─────────────────────────────────────────────────────────────────────────
    # 2018
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2018-7445",
        "title": "SMB Stack Buffer Overflow (Pre-Auth RCE)",
        "description": (
            "A stack buffer overflow in the MikroTik RouterOS SMB service allows "
            "unauthenticated remote attackers to execute arbitrary code via a crafted "
            "SMB NTLMSSP negotiation request. Known as the RouterOS SMB exploit (similar "
            "to EternalBlue targeting). Targets RouterOS SMB daemon listening on TCP/445."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected": [(None, (6, 41, 3))],
        "fixed_in": "6.41.4 / 6.42beta",
        "services": ["smb"],
        "ports": [445],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-7445",
            "https://www.exploit-db.com/exploits/44290",
            "https://github.com/BigNerd95/Chimay-Red",
        ],
        "metasploit": None,
        "notes": (
            "Pre-authentication — no credentials needed. "
            "SMB service not enabled by default on newer RouterOS. "
            "Requires SMB to be enabled (ip smb set enabled=yes)."
        ),
    },
    {
        "cve_id": "CVE-2018-10066",
        "title": "Winbox Authentication Bypass (Directory Traversal)",
        "description": (
            "The Winbox protocol in MikroTik RouterOS allows unauthenticated remote "
            "attackers to bypass authentication and read arbitrary files from the "
            "device filesystem. Precursor vulnerability to CVE-2018-14847."
        ),
        "severity": "HIGH",
        "cvss_score": 8.1,
        "affected": [(None, (6, 41, 99))],
        "fixed_in": "6.42",
        "services": ["winbox"],
        "ports": [8291],
        "poc_available": True,
        "exploit_type": "disclosure",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-10066",
            "https://www.exploit-db.com/exploits/44813",
        ],
        "metasploit": None,
        "notes": "Partial auth bypass; full disclosure achieved via CVE-2018-14847.",
    },
    {
        "cve_id": "CVE-2018-14847",
        "title": "Winbox Credential Disclosure via Directory Traversal (Chimay-Red/EternalWink)",
        "description": (
            "An issue in the Winbox Always ON feature of MikroTik RouterOS allows "
            "unauthenticated remote attackers to read arbitrary files including the "
            "user database (/flash/rw/store/user.dat), disclosing admin password hashes. "
            "Originally from the Vault 7 CIA toolset leak. Exploited in the wild extensively. "
            "Also known as 'Chimay-Red' and 'EternalWink'."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "affected": [(None, (6, 42, 0))],
        "fixed_in": "6.42.1",
        "services": ["winbox"],
        "ports": [8291],
        "poc_available": True,
        "exploit_type": "disclosure",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
            "https://www.exploit-db.com/exploits/45220",
            "https://github.com/BasuCert/WinboxPoC",
            "https://github.com/jas502n/CVE-2018-14847",
            "https://github.com/BigNerd95/Chimay-Red",
        ],
        "metasploit": "auxiliary/gather/mikrotik_winbox_disclosure",
        "notes": (
            "Extremely well-documented and widely exploited. "
            "Works even when Winbox is at default config. "
            "Discloses password hashes which are MD5-based and often crackable."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2019
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2019-3924",
        "title": "RouterOS WWW Server Pre-Auth RCE",
        "description": (
            "The MikroTik RouterOS www service is vulnerable to a pre-authentication "
            "stack buffer overflow via the jsproxy endpoint. An unauthenticated attacker "
            "can achieve remote code execution with root privileges. Often chained with "
            "CVE-2019-3943 to extract credentials and achieve persistent access."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected": [(None, (6, 43, 11))],
        "fixed_in": "6.43.12",
        "services": ["http"],
        "ports": [80, 443],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3924",
            "https://www.exploit-db.com/exploits/46842",
            "https://github.com/jas502n/CVE-2019-3924",
        ],
        "metasploit": "exploit/linux/http/mikrotik_www_exec",
        "notes": (
            "Affects the www server (WebFig). Can be triggered over HTTP without "
            "authentication. Metasploit module available and functional."
        ),
    },
    {
        "cve_id": "CVE-2019-3943",
        "title": "RouterOS HTTP Server Path Traversal",
        "description": (
            "MikroTik RouterOS versions before 6.43.8 have a path traversal vulnerability "
            "in the www server allowing authenticated attackers (and potentially unauthenticated "
            "in combination with other vulnerabilities) to read arbitrary files from the "
            "device filesystem."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 43, 7))],
        "fixed_in": "6.43.8",
        "services": ["http"],
        "ports": [80, 443],
        "poc_available": True,
        "exploit_type": "traversal",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3943",
            "https://www.exploit-db.com/exploits/46731",
        ],
        "metasploit": None,
        "notes": "Commonly chained with CVE-2019-3924 for full exploitation chain.",
    },
    {
        "cve_id": "CVE-2019-3976",
        "title": "RouterOS NPK Arbitrary File Read",
        "description": (
            "MikroTik RouterOS before 6.44.5 and 6.45.x before 6.45.1 is vulnerable "
            "to an arbitrary file read via crafted NPK package files. Allows extraction "
            "of sensitive configuration data."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 44, 4)), ((6, 45, 0), (6, 45, 0))],
        "fixed_in": "6.44.5 / 6.45.1",
        "services": ["api", "winbox"],
        "ports": [8728, 8291],
        "poc_available": True,
        "exploit_type": "disclosure",
        "auth_required": True,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3976",
            "https://github.com/tenable/routeros",
        ],
        "metasploit": None,
        "notes": "Requires ability to upload or stage an NPK file (admin access).",
    },
    {
        "cve_id": "CVE-2019-3977",
        "title": "RouterOS NPK Arbitrary Code Execution",
        "description": (
            "MikroTik RouterOS before 6.44.6 and 6.45.x before 6.45.2 is vulnerable "
            "to arbitrary code execution via a crafted NPK package file during upgrade. "
            "Allows an attacker with upload capability to execute arbitrary code as root."
        ),
        "severity": "HIGH",
        "cvss_score": 7.8,
        "affected": [(None, (6, 44, 5)), ((6, 45, 0), (6, 45, 1))],
        "fixed_in": "6.44.6 / 6.45.2",
        "services": ["api", "ftp", "winbox"],
        "ports": [21, 8728, 8291],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": True,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3977",
            "https://github.com/tenable/routeros",
            "https://medium.com/tenable-techblog/routeros-chain-to-root-44",
        ],
        "metasploit": None,
        "notes": (
            "Requires admin access to upload NPK file. "
            "Can chain with CVE-2018-14847 to get credentials first."
        ),
    },
    {
        "cve_id": "CVE-2019-3978",
        "title": "RouterOS DNS Cache Poisoning",
        "description": (
            "MikroTik RouterOS before 6.44.5 / 6.45.x before 6.45.1 is vulnerable to "
            "DNS cache poisoning when the DNS cache is enabled (allow-remote-requests=yes). "
            "A remote attacker can poison DNS responses for any domain."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 44, 4)), ((6, 45, 0), (6, 45, 0))],
        "fixed_in": "6.44.5 / 6.45.1",
        "services": ["dns"],
        "ports": [53],
        "poc_available": True,
        "exploit_type": "spoofing",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3978",
            "https://github.com/tenable/routeros",
        ],
        "metasploit": None,
        "notes": "Only applicable when allow-remote-requests=yes in /ip dns.",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2020
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-11881",
        "title": "RouterOS DNS Server Heap Buffer Overflow",
        "description": (
            "MikroTik RouterOS 7.x before 7.0beta7 is vulnerable to a heap-based "
            "buffer overflow in the DNS server component when processing malformed "
            "DNS queries. Can lead to denial of service or potential code execution."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((7, 0, 0), (7, 0, 0))],
        "fixed_in": "7.0beta7",
        "services": ["dns"],
        "ports": [53],
        "poc_available": False,
        "exploit_type": "dos",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-11881",
        ],
        "metasploit": None,
        "notes": "Only affects RouterOS 7.x early beta releases.",
    },
    {
        "cve_id": "CVE-2020-20213",
        "title": "RouterOS NPK Upgrade Denial of Service",
        "description": (
            "MikroTik RouterOS 6.44.6 through 6.47.9 and 7.0.x allows remote attackers "
            "to cause a denial of service via crafted NPK package files during system "
            "upgrade processing. Results in router crash or restart."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((6, 44, 6), (6, 47, 9)), ((7, 0, 0), (7, 0, 99))],
        "fixed_in": "6.47.10 / 7.1",
        "services": ["api", "ftp", "winbox"],
        "ports": [21, 8728, 8291],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-20213",
            "https://github.com/cq674350529/pocs/tree/master/routeros",
        ],
        "metasploit": None,
        "notes": "Requires NPK file upload capability (admin or FTP access).",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2021
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-27263",
        "title": "Winbox Authentication Bypass (RouterOS 7.x)",
        "description": (
            "MikroTik RouterOS before 7.1 is vulnerable to an authentication bypass "
            "via the Winbox protocol. An unauthenticated attacker can exploit a flaw "
            "in the M2 authentication phase to gain unauthorized access to the router "
            "management interface."
        ),
        "severity": "HIGH",
        "cvss_score": 8.1,
        "affected": [((7, 0, 0), (7, 0, 99))],
        "fixed_in": "7.1",
        "services": ["winbox"],
        "ports": [8291],
        "poc_available": True,
        "exploit_type": "auth_bypass",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-27263",
            "https://github.com/cq674350529/pocs/tree/master/routeros",
        ],
        "metasploit": None,
        "notes": "Only affects RouterOS 7.0.x — limited deployment window.",
    },
    {
        "cve_id": "CVE-2021-36522",
        "title": "RouterOS www Server Authenticated RCE",
        "description": (
            "MikroTik RouterOS before 6.49.1 / 7.1 is vulnerable to remote code "
            "execution in the www server when an authenticated attacker sends specially "
            "crafted HTTP requests to internal API endpoints. "
            "Allows command injection via the scheduler or scripts API."
        ),
        "severity": "HIGH",
        "cvss_score": 8.0,
        "affected": [(None, (6, 49, 0)), ((7, 0, 0), (7, 0, 99))],
        "fixed_in": "6.49.1 / 7.1",
        "services": ["http", "api"],
        "ports": [80, 8728],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": True,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-36522",
            "https://github.com/jared-barocsi/CVE-2021-36522",
        ],
        "metasploit": None,
        "notes": "Requires authenticated access; uses scheduler/scripts API as RCE vector.",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2022
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2022-34960",
        "title": "RouterOS Container Feature Privilege Escalation",
        "description": (
            "MikroTik RouterOS before 7.5 with the Container package installed allows "
            "a local attacker (or remote attacker with API/Winbox access) to escalate "
            "privileges to root by creating a container with a crafted entrypoint that "
            "mounts sensitive filesystem paths, bypassing RouterOS sandboxing."
        ),
        "severity": "HIGH",
        "cvss_score": 8.4,
        "affected": [((7, 1, 0), (7, 4, 99))],
        "fixed_in": "7.5",
        "services": ["api", "winbox"],
        "ports": [8728, 8291],
        "poc_available": True,
        "exploit_type": "privesc",
        "auth_required": True,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-34960",
            "https://margin.re/2022/06/pulling-mikrotik-into-the-limelight/",
        ],
        "metasploit": None,
        "notes": (
            "Container package must be installed and enabled. "
            "Very powerful: container mounts /nova/ giving full RouterOS root access."
        ),
    },
    {
        "cve_id": "CVE-2022-45315",
        "title": "RouterOS SMB Stack Buffer Overflow (Authenticated RCE)",
        "description": (
            "MikroTik RouterOS before 6.49.7 and 7.x before 7.6 is vulnerable to a "
            "stack-based buffer overflow in the SMB service when processing crafted "
            "SMB requests from an authenticated user. Results in arbitrary code execution "
            "with root privileges."
        ),
        "severity": "HIGH",
        "cvss_score": 8.8,
        "affected": [(None, (6, 49, 6)), ((7, 0, 0), (7, 5, 99))],
        "fixed_in": "6.49.7 / 7.6",
        "services": ["smb"],
        "ports": [445],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": True,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-45315",
            "https://github.com/cq674350529/pocs/tree/master/routeros",
            "https://www.exploit-db.com/exploits/51451",
        ],
        "metasploit": None,
        "notes": (
            "Requires SMB service to be enabled and valid credentials. "
            "SMB not enabled by default."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2023
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-30799",
        "title": "RouterOS Privilege Escalation via supout.rif (FOISted)",
        "description": (
            "MikroTik RouterOS before 6.49.8 / 7.10 is vulnerable to a privilege "
            "escalation attack dubbed 'FOISted'. An admin user (not super-admin) can "
            "escalate to super-admin by uploading a crafted supout.rif diagnostic file "
            "to the router, then leveraging Winbox protocol to read arbitrary files "
            "from the /nova/ filesystem, gaining root-level access."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "affected": [(None, (6, 49, 7)), ((7, 0, 0), (7, 9, 99))],
        "fixed_in": "6.49.8 / 7.10",
        "services": ["api", "winbox"],
        "ports": [8291, 8728],
        "poc_available": True,
        "exploit_type": "privesc",
        "auth_required": True,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-30799",
            "https://github.com/0xjpuff/CVE-2023-30799",
            "https://vulncheck.com/blog/foisted",
        ],
        "metasploit": None,
        "notes": (
            "Requires at minimum 'write' group credentials. "
            "Escalates to super-admin giving full /nova/ filesystem access (jailbreak). "
            "Used in multiple real-world attacks."
        ),
    },
    {
        "cve_id": "CVE-2023-32154",
        "title": "RouterOS IPv6 DHCPv6 Pre-Auth Remote Code Execution",
        "description": (
            "MikroTik RouterOS before 7.9.1 is vulnerable to remote code execution via "
            "malformed DHCPv6 packets when the DHCPv6 client is enabled. An attacker on "
            "the same network segment can send a crafted DHCPv6 message causing a heap "
            "corruption leading to arbitrary code execution as root."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected": [((7, 0, 0), (7, 9, 0))],
        "fixed_in": "7.9.1",
        "services": ["dhcpv6"],
        "ports": [547],
        "poc_available": False,
        "exploit_type": "rce",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-32154",
            "https://www.zerodayinitiative.com/advisories/ZDI-23-1578/",
        ],
        "metasploit": None,
        "notes": (
            "Requires DHCPv6 client to be running (/ipv6 dhcp-client). "
            "Attacker must be on local network segment (link-local scope). "
            "No public PoC but ZDI advisory confirms exploitability."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2024
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2024-27887",
        "title": "RouterOS OSPF Route Injection",
        "description": (
            "MikroTik RouterOS 7.x before 7.14 is vulnerable to OSPF route injection "
            "by an unauthenticated attacker on a connected network segment. By sending "
            "crafted OSPF LSA packets, an attacker can inject arbitrary routes into the "
            "router's routing table, enabling traffic hijacking and man-in-the-middle attacks."
        ),
        "severity": "HIGH",
        "cvss_score": 8.1,
        "affected": [((7, 0, 0), (7, 13, 99))],
        "fixed_in": "7.14",
        "services": ["ospf"],
        "ports": [89],
        "poc_available": True,
        "exploit_type": "injection",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-27887",
            "https://github.com/VulnHub/CVE-2024-27887",
        ],
        "metasploit": None,
        "notes": (
            "Requires OSPF to be configured and active. "
            "Attacker must be on a network reachable by the OSPF area. "
            "Only affects RouterOS 7.0-7.13."
        ),
    },
    {
        "cve_id": "CVE-2024-35274",
        "title": "RouterOS Authenticated RCE via Scheduler/Script Injection",
        "description": (
            "MikroTik RouterOS before 7.15 allows an authenticated admin user to achieve "
            "remote code execution by injecting malicious RouterOS script content via the "
            "scheduler or script subsystem. The scripts are executed by a privileged internal "
            "process with elevated access to the router's /nova/ filesystem."
        ),
        "severity": "HIGH",
        "cvss_score": 8.8,
        "affected": [((7, 0, 0), (7, 14, 99))],
        "fixed_in": "7.15",
        "services": ["api", "winbox", "http"],
        "ports": [8728, 8291, 80],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": True,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-35274",
        ],
        "metasploit": None,
        "notes": (
            "Requires 'write' policy permission or higher. "
            "The scheduler API can be used to create tasks that execute arbitrary code. "
            "This is the 'legitimate feature as exploit' pattern."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # CONFIGURATION/DESIGN VULNERABILITIES (novel findings — no CVE assigned)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "MIKROTIK-CONFIG-001",
        "title": "WireGuard Private Key Exposure via Authenticated REST API",
        "description": (
            "MikroTik RouterOS exposes WireGuard private keys in plaintext through the "
            "REST API endpoint /rest/interface/wireguard. Any admin-authenticated API "
            "client can retrieve the private keys of all WireGuard interfaces. This allows "
            "VPN impersonation, decryption of captured WireGuard traffic, and establishment "
            "of unauthorized VPN tunnels. Design issue — no CVE assigned as of 2026-03."
        ),
        "severity": "HIGH",
        "cvss_score": 7.2,
        "affected": [((7, 0, 0), None)],
        "fixed_in": None,
        "services": ["api", "rest-api"],
        "ports": [8728, 80],
        "poc_available": True,
        "exploit_type": "disclosure",
        "auth_required": True,
        "references": [
            "https://github.com/mrhenrike/MikrotikAPI-BF",
        ],
        "metasploit": None,
        "notes": (
            "Discovered during lab assessment 2026-03-25. "
            "WireGuard only available in RouterOS 7.x+ — not applicable to 6.x. "
            "Mitigation: restrict REST API access by IP and disable www service."
        ),
    },
    {
        "cve_id": "MIKROTIK-CONFIG-002",
        "title": "Packet Sniffer Remote Stream — Wiretapping via API",
        "description": (
            "MikroTik RouterOS provides a packet sniffer tool accessible via the REST API "
            "and Winbox. An authenticated admin can enable remote packet streaming to any "
            "external IP:port via TZSP protocol. This allows exfiltration of all traffic "
            "transiting the router to an attacker-controlled server, effectively turning "
            "the router into a wiretapping device. One API call is sufficient."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, None)],
        "fixed_in": None,
        "services": ["api", "rest-api", "winbox"],
        "ports": [8728, 80, 8291],
        "poc_available": True,
        "exploit_type": "wiretapping",
        "auth_required": True,
        "references": [
            "https://github.com/mrhenrike/MikrotikAPI-BF",
            "https://wiki.mikrotik.com/wiki/Manual:Tools/Packet_Sniffer",
        ],
        "metasploit": None,
        "notes": (
            "Design feature used as attack capability. "
            "Payload: PUT /rest/tool/sniffer with streaming-enabled=true and "
            "streaming-server=<attacker-ip>:37008. No patch — admin access prevention only."
        ),
    },
    {
        "cve_id": "MIKROTIK-JAILBREAK-001",
        "title": "RouterOS Jailbreak via Backup Path Traversal (SSH)",
        "description": (
            "MikroTik RouterOS 2.9.8 through 6.41rc56 allows an authenticated "
            "SSH user to create a 'devel' user by exploiting path traversal in "
            "the backup restore mechanism. The patched backup injects a devel-login "
            "entry into /nova/etc/, granting a full Linux telnet shell."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.0,
        "affected": [((2, 9, 8), (6, 42, 0))],
        "fixed_in": "6.42",
        "services": ["ssh"],
        "ports": [22],
        "poc_available": True,
        "exploit_type": "privesc",
        "auth_required": True,
        "references": [
            "https://github.com/0ki/mikrotik-tools",
        ],
        "metasploit": None,
        "notes": (
            "Requires valid SSH credentials. Creates 'devel' user for Linux shell. "
            "After restore, telnet devel/<admin_password> gives root shell."
        ),
    },
    {
        "cve_id": "CVE-2018-14847-DECRYPT",
        "title": "Winbox Full Credential Extraction and Decryption",
        "description": (
            "Extension of CVE-2018-14847 that not only detects the user.dat "
            "disclosure but fully extracts and decrypts all stored credentials "
            "using the RouterOS MD5-based key derivation scheme. Returns actual "
            "username/password pairs in plaintext."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "affected": [(None, (6, 42, 0))],
        "fixed_in": "6.42.1",
        "services": ["winbox"],
        "ports": [8291],
        "poc_available": True,
        "exploit_type": "disclosure",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
            "https://github.com/BasuCert/WinboxPoC",
            "https://n0p.me/winbox-bug-dissection/",
        ],
        "metasploit": "auxiliary/gather/mikrotik_winbox_disclosure",
        "notes": (
            "Full credential decryption using MD5(user + '283i4jfkai3389') key. "
            "Returns plaintext passwords for all local users."
        ),
    },
    {
        "cve_id": "MIKROTIK-CONFIG-004",
        "title": "Scheduler/Script Command Injection via REST API",
        "description": (
            "MikroTik RouterOS REST API allows authenticated administrators to "
            "create scheduler entries with arbitrary RouterOS script commands in "
            "the on-event field. These execute with full system privileges, enabling "
            "persistence (scheduled backdoor tasks), lateral movement (SSRF chains), "
            "and data exfiltration (DNS/HTTP exfil via resolve/fetch). By-design "
            "feature used as a post-authentication attack vector."
        ),
        "severity": "HIGH",
        "cvss_score": 7.2,
        "affected": [(None, None)],
        "fixed_in": None,
        "services": ["rest-api", "api"],
        "ports": [80, 443, 8728],
        "poc_available": True,
        "exploit_type": "injection",
        "auth_required": True,
        "references": [
            "https://github.com/mrhenrike/MikrotikAPI-BF",
        ],
        "metasploit": None,
        "notes": (
            "By-design: admin can schedule commands. Attack value: persistence, "
            "C2 callbacks, DNS exfil via :resolve, data theft via /tool/fetch. "
            "No sanitization of on-event field — stored verbatim."
        ),
    },
    {
        "cve_id": "MIKROTIK-CONFIG-005",
        "title": "REST API Path Traversal Probe",
        "description": (
            "Tests whether the MikroTik RouterOS REST API endpoint parser is "
            "vulnerable to directory traversal, null-byte injection, or command "
            "chaining via crafted URI paths. Probes ../../../etc/passwd, "
            "URL-encoded sequences, null bytes, and inline command separators."
        ),
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected": [(None, None)],
        "fixed_in": None,
        "services": ["rest-api"],
        "ports": [80, 443],
        "poc_available": True,
        "exploit_type": "traversal",
        "auth_required": True,
        "references": [
            "https://github.com/mrhenrike/MikrotikAPI-BF",
        ],
        "metasploit": None,
        "notes": (
            "Audit probe — tests if REST API has path traversal. "
            "Modern RouterOS typically blocks these vectors. "
            "Useful for regression testing after firmware updates."
        ),
    },
    {
        "cve_id": "MIKROTIK-CONFIG-003",
        "title": "SSRF via REST API tool/fetch Endpoint",
        "description": (
            "MikroTik RouterOS REST API endpoint /rest/tool/fetch allows an "
            "authenticated administrator to make arbitrary HTTP/FTP requests from "
            "the router's network context. This enables internal service access "
            "(127.0.0.1, [::1] on any port), cloud metadata theft (169.254.169.254 "
            "in AWS/GCP/Azure), and network pivoting using the router as an SSRF proxy. "
            "Particularly dangerous on CHR deployments in cloud environments where "
            "instance credentials are accessible via metadata service."
        ),
        "severity": "HIGH",
        "cvss_score": 7.2,
        "affected": [((7, 0, 0), None)],
        "fixed_in": None,
        "services": ["rest-api"],
        "ports": [80, 443],
        "poc_available": True,
        "exploit_type": "ssrf",
        "auth_required": True,
        "references": [
            "https://github.com/mrhenrike/MikrotikAPI-BF",
        ],
        "metasploit": None,
        "notes": (
            "Discovered during lab assessment 2026-04. "
            "REST API only (RouterOS 7.x+). No CVE assigned — by-design feature. "
            "CWE-918 (Server-Side Request Forgery). "
            "Mitigation: restrict REST API access by IP, audit tool/fetch usage."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # CVE-2018-14847-MAC variant (Layer-2 MNDP/MAC-server delivery)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2018-14847-MAC",
        "title": "Winbox Credential Disclosure via MAC-Server/MNDP (Layer-2)",
        "description": (
            "Extension of CVE-2018-14847 leveraging MNDP (MikroTik Neighbor Discovery "
            "Protocol) on UDP port 20561 to discover devices in the local Layer-2 segment, "
            "including switches and APs with no IP assigned. The same Winbox file-read "
            "payload is then sent to each discovered device's IP:8291. "
            "Particularly useful against unconfigured or factory-reset hardware. "
            "LAYER-2 ONLY: cannot traverse Layer-3 routers."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.1,
        "affected": [(None, (6, 42, 0))],
        "fixed_in": "6.42.1",
        "services": ["winbox", "mac-server"],
        "ports": [20561, 8291],
        "poc_available": True,
        "exploit_type": "disclosure",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
            "https://github.com/BasuCert/WinboxPoC/blob/master/MACServerExploit.py",
            "https://blog.mikrotik.com/security/winbox-vulnerability.html",
            "https://blog.n0p.me/2018/05/2018-05-21-winbox-bug-dissection/",
            "https://mikrotik.com/supportsec/winbox-vulnerability/",
            "https://wiki.mikrotik.com/wiki/MNDP",
        ],
        "metasploit": "auxiliary/gather/mikrotik_winbox_disclosure",
        "notes": (
            "Layer-2 constraint: attacker must be on the same VLAN/switch segment. "
            "Same fix as CVE-2018-14847 (RouterOS 6.42.1+). "
            "Disable MAC-Server if not needed: /ip neighbor discovery-settings set discover-interface-list=none. "
            "Disable MAC-Winbox-Server: /tool mac-server set allowed-interface-list=none."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2020
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-20215",
        "title": "RouterOS MPLS Out-of-Bounds Write (Denial of Service)",
        "description": (
            "MikroTik RouterOS before 6.47 contains an out-of-bounds write vulnerability "
            "in the MPLS implementation. A specially crafted MPLS packet can cause the "
            "router to crash, resulting in a denial-of-service condition. "
            "Affects all RouterOS builds with MPLS enabled before 6.47."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47",
        "services": ["mpls"],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-20215",
            "https://mikrotik.com/download/changelogs",
        ],
        "metasploit": None,
        "notes": (
            "Affects RouterOS < 6.47 (all stable/long-term builds). "
            "Disable MPLS if not in use: /mpls set enabled=no. "
            "Update to 6.47+ to patch."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2021
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-41987",
        "title": "RADIUS Client Stack-Based Buffer Overflow",
        "description": (
            "A stack-based buffer overflow in the RADIUS client of MikroTik RouterOS "
            "before 6.49.1 and 7.1 allows a malicious RADIUS server to crash the router "
            "or potentially execute arbitrary code by returning a crafted Access-Accept "
            "packet with an oversized attribute. Requires the router to have RADIUS "
            "authentication enabled and configured to reach the attacker-controlled server."
        ),
        "severity": "HIGH",
        "cvss_score": 8.1,
        "affected": [(None, (6, 49, 0)), ((7, 0, 0), (7, 0, 99))],
        "fixed_in": "6.49.1 / 7.1",
        "services": ["radius"],
        "ports": [1812, 1813],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2021-41987",
            "https://mikrotik.com/download/changelogs",
        ],
        "metasploit": None,
        "notes": (
            "Requires: (1) RADIUS enabled on router, (2) attacker controls RADIUS server. "
            "Exploitation: MitM the RADIUS server or compromise it; return crafted packet. "
            "Mitigation: update to 6.49.1+ / 7.1+; use only trusted RADIUS servers; "
            "isolate management network."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2023
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-30800",
        "title": "WWW Service Stack-Based Buffer Overflow (Pre-Auth DoS/RCE)",
        "description": (
            "A stack-based buffer overflow in the MikroTik RouterOS www HTTP service "
            "allows a remote unauthenticated attacker to crash the web management service "
            "or potentially execute arbitrary code by sending an HTTP request with an "
            "oversized cookie header (>= 8192 bytes). Related to and distinct from "
            "CVE-2023-30799 (FOISted). Affects RouterOS and RouterOS CHR."
        ),
        "severity": "HIGH",
        "cvss_score": 8.2,
        "affected": [(None, (6, 49, 8)), ((7, 0, 0), (7, 9, 99))],
        "fixed_in": "6.49.9 / 7.10 (pending)",
        "services": ["http", "www"],
        "ports": [80, 443],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-30800",
            "https://vulncheck.com/advisories/vc-advisory-VCSA-0085",
            "https://github.com/mrhenrike/MikrotikAPI-BF",
        ],
        "metasploit": None,
        "notes": (
            "Pre-authentication — no credentials needed. "
            "Send HTTP GET with Cookie: header >= 8192 bytes. "
            "Mitigation: disable www service if not needed (/ip service disable www); "
            "restrict www access by IP (/ip service set www address=<mgmt-net>)."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2024
    # ─────────────────────────────────────────────────────────────────────────
    # ─────────────────────────────────────────────────────────────────────────
    # 2017 (additional)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2017-20149",
        "title": "RouterOS www Password Exposure in HTTP Response",
        "description": (
            "In certain MikroTik RouterOS versions before 6.38.5, the web management "
            "interface leaks the admin password hash or plaintext in HTTP response "
            "headers or body under specific conditions. Also tracked as the 'TikTok' "
            "vulnerability."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected": [(None, (6, 38, 4))],
        "fixed_in": "6.38.5",
        "services": ["http", "www"],
        "ports": [80],
        "poc_available": True,
        "exploit_type": "disclosure",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2017-20149",
        ],
        "metasploit": None,
        "notes": (
            "Pre-authentication — no credentials needed. "
            "Affects very old RouterOS versions (< 6.38.5)."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2019 (additional)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2019-3981",
        "title": "RouterOS DNS Forwarder MitM / Cache Poisoning",
        "description": (
            "MikroTik RouterOS before 6.45.7 DNS forwarder uses predictable source "
            "ports and transaction IDs, enabling DNS cache poisoning when "
            "allow-remote-requests=yes. An attacker can redirect DNS queries through "
            "the router via a MitM attack."
        ),
        "severity": "MEDIUM",
        "cvss_score": 5.9,
        "affected": [(None, (6, 45, 6))],
        "fixed_in": "6.45.7",
        "services": ["dns"],
        "ports": [53],
        "poc_available": True,
        "exploit_type": "spoofing",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3981",
            "https://github.com/tenable/routeros",
        ],
        "metasploit": None,
        "notes": (
            "Requires allow-remote-requests=yes in /ip dns. "
            "Only exploitable when router acts as DNS forwarder."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2020 (additional)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-5720",
        "title": "RouterOS UDP Fragment Crash (Packet of Death)",
        "description": (
            "A specially crafted fragmented UDP packet causes MikroTik RouterOS "
            "to crash and reboot. This is a denial-of-service vulnerability that "
            "requires IP-level access to the device."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 46, 4))],
        "fixed_in": "6.46.5 / 6.47 (long-term)",
        "services": ["ip"],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2020-5720",
        ],
        "metasploit": None,
        "notes": (
            "Requires IP-level access. Crafted fragmented UDP packet triggers crash. "
            "Update to 6.46.5+ or 6.47+ to patch."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2022 (additional)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2022-45313",
        "title": "RouterOS SMB Heap Use-After-Free (Pre-Auth RCE)",
        "description": (
            "A heap use-after-free vulnerability in the MikroTik RouterOS SMB "
            "service allows pre-authenticated remote code execution. Different from "
            "CVE-2022-45315 (authenticated stack overflow). An unauthenticated "
            "attacker can send crafted SMB negotiate requests to trigger the UAF."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.8,
        "affected": [(None, (6, 49, 6)), ((7, 0, 0), (7, 5, 99))],
        "fixed_in": "6.49.7 / 7.6",
        "services": ["smb"],
        "ports": [445],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2022-45313",
            "https://www.exploit-db.com/exploits/51451",
        ],
        "metasploit": None,
        "notes": (
            "Pre-authentication — no credentials needed. "
            "SMB must be enabled. Not enabled by default on most RouterOS builds."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2025
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2025-6563",
        "title": "RouterOS 7.x WebFig Reflected XSS / Open Redirect",
        "description": (
            "MikroTik RouterOS 7.x WebFig web interface is vulnerable to reflected "
            "cross-site scripting and open redirect via crafted URL parameters. "
            "An attacker can steal admin session tokens or redirect admins to "
            "attacker-controlled pages."
        ),
        "severity": "MEDIUM",
        "cvss_score": 6.1,
        "affected": [((7, 0, 0), (7, 19, 0))],
        "fixed_in": "7.19.1 (partial)",
        "services": ["http", "www"],
        "ports": [80, 443],
        "poc_available": True,
        "exploit_type": "xss",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-6563",
            "https://www.exploit-db.com/exploits/52366",
        ],
        "metasploit": None,
        "notes": (
            "Requires victim to click crafted URL. "
            "Can be used to steal admin cookies/tokens. "
            "Partial fix in 7.19.1."
        ),
    },
    {
        "cve_id": "CVE-2025-61481",
        "title": "WebFig HTTP Credential Exposure and Information Leak",
        "description": (
            "MikroTik RouterOS and SwitchOS WebFig (web management interface) "
            "transmits HTTP Basic Auth credentials in cleartext when accessed "
            "over plain HTTP. A network observer or MITM attacker can capture "
            "admin credentials. Additionally, certain REST API endpoints leak "
            "device identity, firmware version, and RouterBOARD info without "
            "authentication, enabling reconnaissance."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, None)],
        "fixed_in": None,
        "services": ["http", "rest-api"],
        "ports": [80, 443],
        "poc_available": True,
        "exploit_type": "disclosure",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-61481",
            "https://github.com/mrhenrike/MikrotikAPI-BF",
        ],
        "metasploit": None,
        "notes": (
            "Affects any RouterOS version with WebFig over HTTP. "
            "Fix: enable HTTPS, disable plain HTTP service, restrict by IP."
        ),
    },
    {
        "cve_id": "CVE-2025-10948",
        "title": "REST API Stack-Based Buffer Overflow (Authenticated RCE)",
        "description": (
            "A stack-based buffer overflow in the MikroTik RouterOS 7 REST API "
            "HTTP request processing layer when parsing malformed Accept-Language "
            "or long custom headers. Any authenticated REST API user (even read-only) "
            "can trigger the overflow, crashing the REST daemon or achieving arbitrary "
            "code execution. Combined with default blank admin credentials, this "
            "achieves unauthenticated full router compromise."
        ),
        "severity": "HIGH",
        "cvss_score": 8.8,
        "affected": [((7, 0, 0), (7, 16, 1))],
        "fixed_in": "7.16.2",
        "services": ["http", "rest-api"],
        "ports": [80, 443],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": True,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2025-10948",
            "https://zeropath.com/blog/cve-2025-10948-mikrotik-routeros-buffer-overflow",
            "https://mikrotik.com/security/bulletins/CVE-2025-10948",
        ],
        "metasploit": None,
        "notes": (
            "RouterOS 7.0–7.16.1 only. "
            "Trigger: 4096-byte Accept-Language header to any /rest/* endpoint. "
            "Fix: upgrade to 7.16.2+. Workaround: disable REST API or restrict by IP."
        ),
    },
    {
        "cve_id": "CVE-2024-2169",
        "title": "BFD Protocol Reflection / Amplification Loop (DoS)",
        "description": (
            "MikroTik RouterOS and other BFD implementations may be abused for "
            "Bidirectional Forwarding Detection (BFD) reflection/amplification attacks. "
            "An attacker can spoof the source address of a BFD Control packet, causing "
            "the router to send amplified responses to the spoofed victim IP. "
            "This enables reflection-based volumetric DDoS amplification (BFD echo loop). "
            "No authentication is required; BFD operates at the network layer."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, None)],
        "fixed_in": "Requires BFD with authentication (MD5/SHA-1) or BFD isolation; "
                    "no single RouterOS patch — protocol-level mitigation required",
        "services": ["bfd"],
        "ports": [3784, 3785],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2024-2169",
            "https://blog.bfd-vulnerability.com/cve-2024-2169/",
            "https://www.cisecurity.org/advisory/cve-2024-2169",
        ],
        "metasploit": None,
        "notes": (
            "Protocol-level flaw. Mitigation: (1) enable BFD authentication; "
            "(2) filter BFD packets (UDP 3784/3785) at network edge; "
            "(3) disable BFD if not required in network design. "
            "Affects all RouterOS versions with BFD enabled."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # EDB Entries — Exploit-DB verified PoCs (synced to EXPLOIT_REGISTRY)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "EDB-31102",
        "title": "RouterOS 3.x SNMP SET Denial of Service",
        "description": "Crafted SNMP SET packet crashes SNMPd daemon on RouterOS <= 3.2.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (3, 2, 99))],
        "fixed_in": "3.3+",
        "services": ["snmp"],
        "ports": [161],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/31102"],
        "metasploit": None,
        "notes": "Very old RouterOS; SNMP must be enabled.",
    },
    {
        "cve_id": "EDB-6366",
        "title": "RouterOS 3.13 SNMP Unauthorized Write (Set Request)",
        "description": (
            "RouterOS <= 3.13 accepts SNMP SET requests despite documentation claiming "
            "read-only support, allowing unauthenticated OID modification (CVE-2008-6976)."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((2, 9, 51), (3, 13, 99))],
        "fixed_in": "3.14+",
        "services": ["snmp"],
        "ports": [161],
        "poc_available": True,
        "exploit_type": "config_modify",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/6366"],
        "metasploit": None,
        "notes": "Also tracked as CVE-2008-6976.",
    },
    {
        "cve_id": "EDB-44283/44284",
        "title": "Chimay Red — Stack Clash Pre-Auth RCE",
        "description": (
            "The www HTTP service in RouterOS < 6.38.4 is vulnerable to a Stack Clash "
            "attack allowing pre-authenticated remote code execution. Two PoCs exist "
            "for MIPSBE (EDB-44283) and x86/CHR (EDB-44284) architectures."
        ),
        "severity": "CRITICAL",
        "cvss_score": 10.0,
        "affected": [(None, (6, 38, 3))],
        "fixed_in": "6.38.4+",
        "services": ["http", "www"],
        "ports": [80],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": False,
        "references": [
            "https://www.exploit-db.com/exploits/44283",
            "https://www.exploit-db.com/exploits/44284",
            "https://github.com/BigNerd95/Chimay-Red",
        ],
        "metasploit": None,
        "notes": "Pre-auth RCE via www service. Disable HTTP if not needed.",
    },
    {
        "cve_id": "EDB-44450",
        "title": "MikroTik 6.41.4 FTP Daemon Denial of Service",
        "description": "FTP daemon crashes on excessively long username during auth handshake.",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected": [((6, 41, 4), (6, 41, 4))],
        "fixed_in": "6.41.5+",
        "services": ["ftp"],
        "ports": [21],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/44450"],
        "metasploit": None,
        "notes": "Disable FTP service or upgrade.",
    },
    {
        "cve_id": "EDB-43317",
        "title": "MikroTik 6.40.5 ICMP Denial of Service",
        "description": "Crafted ICMP flood causes DoS on RouterOS 6.40.5.",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected": [((6, 40, 5), (6, 40, 5))],
        "fixed_in": "6.40.6+",
        "services": ["icmp"],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/43317"],
        "metasploit": None,
        "notes": "Affects only RouterOS 6.40.5 exactly.",
    },
    {
        "cve_id": "EDB-41752",
        "title": "RouterBoard 6.38.5 Denial of Service",
        "description": "DoS condition on RouterOS 6.38.5.",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected": [((6, 38, 5), (6, 38, 5))],
        "fixed_in": "6.38.6+",
        "services": [],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/41752"],
        "metasploit": None,
        "notes": "Affects only RouterOS 6.38.5 exactly.",
    },
    {
        "cve_id": "EDB-41601",
        "title": "MikroTik Router ARP Table Overflow DoS",
        "description": (
            "Flooding the router with ARP requests fills the ARP table causing DoS. "
            "Requires L2 adjacency (same VLAN/switch)."
        ),
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, None)],
        "fixed_in": "Mitigate: /ip arp set max-entries=<limit>",
        "services": ["arp"],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/41601"],
        "metasploit": None,
        "notes": "Layer-2 attack; requires same broadcast domain.",
    },
    {
        "cve_id": "EDB-28056",
        "title": "RouterOS ROSSSH sshd Remote Heap Corruption",
        "description": (
            "MikroTik ROSSSH SSH daemon is vulnerable to remote heap corruption "
            "via malformed SSH2_MSG_KEXINIT packets during key exchange."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, None)],
        "fixed_in": "Check for ROSSSH banner and upgrade",
        "services": ["ssh"],
        "ports": [22],
        "poc_available": True,
        "exploit_type": "rce",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/28056"],
        "metasploit": None,
        "notes": "Detects ROSSSH banner; pre-auth.",
    },
    {
        "cve_id": "EDB-24968",
        "title": "Mikrotik Syslog Server for Windows 1.15 — Remote BoF DoS",
        "description": (
            "MT_Syslog.exe v1.15 crashes when receiving oversized syslog UDP message. "
            "Targets the Windows companion application, NOT RouterOS firmware."
        ),
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected": [(None, None)],
        "fixed_in": "Upgrade MT_Syslog.exe or switch to another syslog collector",
        "services": ["syslog"],
        "ports": [514],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/24968"],
        "metasploit": None,
        "notes": "Targets Windows app MT_Syslog.exe, not RouterOS.",
    },
    {
        "cve_id": "EDB-18817",
        "title": "Mikrotik Router Generic Denial of Service",
        "description": "Generic DoS condition on multiple RouterOS versions.",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected": [(None, None)],
        "fixed_in": "Upgrade to latest RouterOS",
        "services": [],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/18817"],
        "metasploit": None,
        "notes": "Generic DoS; version check based.",
    },
    {
        "cve_id": "EDB-52366",
        "title": "RouterOS 7.19.1 WebFig Reflected XSS",
        "description": (
            "WebFig interface in RouterOS 7.19.1 reflects user-supplied input in error "
            "messages without HTML encoding, enabling reflected XSS."
        ),
        "severity": "MEDIUM",
        "cvss_score": 6.1,
        "affected": [((7, 19, 1), (7, 19, 1))],
        "fixed_in": "7.19.2+",
        "services": ["http", "webfig"],
        "ports": [80],
        "poc_available": True,
        "exploit_type": "xss",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/52366"],
        "metasploit": None,
        "notes": "Reflected XSS; requires admin to click crafted URL.",
    },
    {
        "cve_id": "EDB-48474",
        "title": "Mikrotik Router Monitoring System 1.2.3 SQL Injection",
        "description": (
            "Third-party PHP web app 'Mikrotik Router Monitoring System' v1.2.3 "
            "is vulnerable to SQL injection. NOT RouterOS firmware."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, None)],
        "fixed_in": "Upgrade monitoring app or remove",
        "services": ["http"],
        "ports": [80],
        "poc_available": True,
        "exploit_type": "sqli",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/48474"],
        "metasploit": None,
        "notes": "Third-party PHP app, not RouterOS itself.",
    },
    {
        "cve_id": "EDB-39817",
        "title": "Web Interface for DNSmasq / Mikrotik — SQL Injection",
        "description": (
            "Third-party PHP web frontend 'dns_dhcp' is vulnerable to error-based "
            "SQL injection via the 'net' POST parameter. NOT RouterOS firmware."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, None)],
        "fixed_in": "Remove or patch dns_dhcp app",
        "services": ["http"],
        "ports": [80],
        "poc_available": True,
        "exploit_type": "sqli",
        "auth_required": False,
        "references": ["https://www.exploit-db.com/exploits/39817"],
        "metasploit": None,
        "notes": "Third-party PHP app, not RouterOS itself.",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # VU#375660 — RouterOS API Brute-Force (No Rate-Limiting)
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "VU-375660",
        "title": "RouterOS API Missing Rate-Limiting (CWE-307)",
        "description": (
            "The MikroTik RouterOS binary API (TCP/8728) and REST API (TCP/80/443) "
            "do not implement effective rate-limiting or account lockout mechanisms. "
            "v7.20.8-LTS has zero throttling; v7.22.1 adds a fixed ~0.13s per-connection "
            "delay easily bypassed by parallel connections. No progressive backoff or "
            "account lockout exists in default configuration, violating NIST SP 800-63B-4 "
            "and OWASP ASVS requirements."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, None)],
        "fixed_in": "No effective fix as of 7.22.1; requires external firewall rules",
        "services": ["api", "rest-api"],
        "ports": [8728, 8729, 80, 443],
        "poc_available": True,
        "exploit_type": "brute_force",
        "auth_required": False,
        "references": [
            "https://kb.cert.org/vuls/id/375660",
            "https://pages.nist.gov/800-63-4/sp800-63b.html",
        ],
        "metasploit": None,
        "notes": (
            "Reported by André Henrique (@mrhenrike) via CERT/CC VINCE. "
            "The core functionality of MikrotikAPI-BF itself IS the PoC for this vulnerability. "
            "Mitigate with /ip firewall filter address-list and connection rate rules."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # Missing CVEs — DNS, DHCPv6, NPK
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-11881",
        "title": "RouterOS DNS Server Heap Buffer Overflow",
        "description": (
            "A heap buffer overflow in the RouterOS DNS server allows a remote "
            "unauthenticated attacker to cause a denial of service by sending "
            "crafted DNS queries."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 46, 5))],
        "fixed_in": "6.46.6 / 6.47",
        "services": ["dns"],
        "ports": [53],
        "poc_available": False,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-11881"],
        "metasploit": None,
        "notes": "Pre-auth DNS DoS. Disable DNS cache/server if not needed.",
    },
    {
        "cve_id": "CVE-2020-20213",
        "title": "RouterOS NPK Upgrade Denial of Service",
        "description": (
            "A denial of service via a crafted NPK upgrade package on MikroTik "
            "RouterOS. Malformed NPK triggers crash during upgrade process."
        ),
        "severity": "MEDIUM",
        "cvss_score": 5.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ["upgrade"],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20213"],
        "metasploit": None,
        "notes": "Requires ability to upload NPK package (authenticated).",
    },
    {
        "cve_id": "CVE-2023-32154",
        "title": "RouterOS IPv6 DHCPv6 Pre-Auth Remote Code Execution",
        "description": (
            "RouterOS IPv6 advertisement receiver does not properly validate DHCPv6 "
            "messages, allowing adjacent network attackers to execute arbitrary code "
            "without authentication. Disclosed via ZDI-23-717."
        ),
        "severity": "CRITICAL",
        "cvss_score": 9.6,
        "affected": [((6, 0, 0), (6, 49, 7)), ((7, 0, 0), (7, 9, 99))],
        "fixed_in": "6.49.8 / 7.10+",
        "services": ["ipv6", "dhcpv6"],
        "ports": [],
        "poc_available": False,
        "exploit_type": "rce",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2023-32154",
            "https://www.zerodayinitiative.com/advisories/ZDI-23-717/",
        ],
        "metasploit": None,
        "notes": (
            "Adjacent network attack (AV:A). Disable IPv6 if not required or "
            "upgrade firmware. ZDI-23-717. Very high impact."
        ),
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2025 — VXLAN Access Control Bypass
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2025-6443",
        "title": "VXLAN Access Control Bypass",
        "description": (
            "RouterOS < 7.20 fails to enforce proper access controls on VXLAN "
            "interfaces, allowing adjacent network attackers to bypass L2/L3 "
            "isolation and reach internal network segments."
        ),
        "severity": "HIGH",
        "cvss_score": 7.2,
        "affected": [((7, 0, 0), (7, 19, 99))],
        "fixed_in": "7.20+",
        "services": ["vxlan"],
        "ports": [4789],
        "poc_available": False,
        "exploit_type": "acl_bypass",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2025-6443"],
        "metasploit": None,
        "notes": "Adjacent network vector. Disable VXLAN or upgrade to 7.20+.",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2024 — SMB & Winbox
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2024-54952",
        "title": "SMB Service Null Pointer Dereference DoS",
        "description": "SMB service in RouterOS 6.40.5 crashes due to null pointer dereference.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((6, 40, 5), (6, 40, 5))],
        "fixed_in": "6.40.6+ or disable SMB",
        "services": ["smb"],
        "ports": [445],
        "poc_available": False,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-54952"],
        "metasploit": None,
        "notes": "SMB must be enabled. Very specific version.",
    },
    {
        "cve_id": "CVE-2024-54772",
        "title": "Winbox Username Enumeration",
        "description": (
            "Winbox protocol in RouterOS v6.43 through 7.17.2 allows remote attackers "
            "to enumerate valid usernames via timing differences in auth responses."
        ),
        "severity": "MEDIUM",
        "cvss_score": 5.4,
        "affected": [((6, 43, 0), (7, 17, 2))],
        "fixed_in": "7.17.3+",
        "services": ["winbox"],
        "ports": [8291],
        "poc_available": True,
        "exploit_type": "info_leak",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2024-54772"],
        "metasploit": None,
        "notes": "Timing-based user enumeration; useful for targeted brute-force.",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2023 — IPv6, REST API
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2023-24094",
        "title": "Bridge2 Daemon Out-of-Bounds Write DoS",
        "description": "Out-of-bounds write in bridge2 daemon causes DoS on RouterOS 6.40.5.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((6, 40, 5), (6, 40, 5))],
        "fixed_in": "6.40.6+",
        "services": ["bridge"],
        "ports": [],
        "poc_available": False,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-24094"],
        "metasploit": None,
        "notes": "Specific to 6.40.5.",
    },
    {
        "cve_id": "CVE-2023-47310",
        "title": "IPv6 UDP Traceroute Firewall Bypass",
        "description": (
            "RouterOS 7 before 7.14 fails to properly handle IPv6 UDP traceroute packets, "
            "allowing attackers to bypass firewall rules."
        ),
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [((7, 0, 0), (7, 13, 99))],
        "fixed_in": "7.14+",
        "services": ["ipv6", "firewall"],
        "ports": [],
        "poc_available": False,
        "exploit_type": "acl_bypass",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-47310"],
        "metasploit": None,
        "notes": "IPv6 firewall bypass; upgrade to 7.14+.",
    },
    {
        "cve_id": "CVE-2023-41570",
        "title": "REST API Access Control Bypass",
        "description": (
            "RouterOS v7.1 through 7.11 REST API fails to enforce proper access controls, "
            "allowing authenticated low-privilege users to access restricted endpoints."
        ),
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected": [((7, 1, 0), (7, 11, 99))],
        "fixed_in": "7.12+",
        "services": ["rest-api"],
        "ports": [80, 443],
        "poc_available": False,
        "exploit_type": "acl_bypass",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2023-41570"],
        "metasploit": None,
        "notes": "Authenticated privilege escalation via REST API.",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2021 — FTP, XSS, PTP, TR069
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2021-27221",
        "title": "FTP Arbitrary .rsc File Overwrite",
        "description": (
            "Authenticated FTP users can overwrite arbitrary .rsc script files on "
            "RouterOS 6.47.9, potentially leading to configuration tampering or RCE."
        ),
        "severity": "HIGH",
        "cvss_score": 8.1,
        "affected": [(None, (6, 47, 9))],
        "fixed_in": "6.47.10+ / 6.48+",
        "services": ["ftp"],
        "ports": [21],
        "poc_available": True,
        "exploit_type": "file_write",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-27221"],
        "metasploit": None,
        "notes": "Requires FTP credentials but leads to config/script overwrite.",
    },
    {
        "cve_id": "CVE-2021-3014",
        "title": "Hotspot Login Page Reflected XSS",
        "description": "Reflected XSS in MikroTik Hotspot captive portal login page.",
        "severity": "MEDIUM",
        "cvss_score": 6.1,
        "affected": [(None, None)],
        "fixed_in": "Check MikroTik advisory; customize hotspot template to sanitize input",
        "services": ["hotspot", "http"],
        "ports": [80, 443],
        "poc_available": True,
        "exploit_type": "xss",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-3014"],
        "metasploit": None,
        "notes": "Affects hotspot captive portal; client-side attack.",
    },
    {
        "cve_id": "CVE-2021-36613",
        "title": "PTP Process NULL Pointer Dereference DoS",
        "description": "NULL pointer dereference in PTP process on RouterOS < 6.48.2.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 48, 1))],
        "fixed_in": "6.48.2+",
        "services": ["ptp"],
        "ports": [319, 320],
        "poc_available": False,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-36613"],
        "metasploit": None,
        "notes": "PTP must be configured.",
    },
    {
        "cve_id": "CVE-2021-36614",
        "title": "TR069-Client NULL Pointer Dereference DoS",
        "description": "NULL pointer dereference in TR069 client on RouterOS < 6.48.2.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 48, 1))],
        "fixed_in": "6.48.2+",
        "services": ["tr069"],
        "ports": [],
        "poc_available": False,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-36614"],
        "metasploit": None,
        "notes": "TR069 must be configured.",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2020 — FTP/SMB BoF, SSH DoS
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-22845",
        "title": "FTP Buffer Overflow Denial of Service",
        "description": "Buffer overflow in FTP service causes DoS on RouterOS <= 6.47.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 47, 0))],
        "fixed_in": "6.47+",
        "services": ["ftp"],
        "ports": [21],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-22845"],
        "metasploit": None,
        "notes": "Disable FTP or upgrade.",
    },
    {
        "cve_id": "CVE-2020-22844",
        "title": "SMB Buffer Overflow Denial of Service",
        "description": "Buffer overflow in SMB service causes DoS on RouterOS <= 6.47.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 47, 0))],
        "fixed_in": "6.47+",
        "services": ["smb"],
        "ports": [445],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-22844"],
        "metasploit": None,
        "notes": "SMB must be enabled. Disable or upgrade.",
    },
    {
        "cve_id": "CVE-2020-20021",
        "title": "SSH Daemon Resource Exhaustion DoS",
        "description": "SSH daemon resource exhaustion on RouterOS <= 6.46.3 allows remote DoS.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 46, 3))],
        "fixed_in": "6.46.4+",
        "services": ["ssh"],
        "ports": [22],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20021"],
        "metasploit": None,
        "notes": "Pre-auth SSH DoS.",
    },
    {
        "cve_id": "CVE-2020-10364",
        "title": "SSH Daemon DoS (Reboot Trigger)",
        "description": "SSH daemon flaw on RouterOS <= 6.44.3 allows remote attacker to cause router reboot.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 44, 3))],
        "fixed_in": "6.44.4+",
        "services": ["ssh"],
        "ports": [22],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-10364"],
        "metasploit": None,
        "notes": "Causes full router reboot; pre-auth.",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2019 — DNS Cache Poisoning
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2019-3979",
        "title": "RouterOS DNS Cache Poisoning",
        "description": (
            "RouterOS DNS resolver uses predictable transaction IDs and source ports, "
            "allowing remote attackers to poison the DNS cache."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [(None, (6, 45, 6))],
        "fixed_in": "6.45.7 / 6.44.6 LTS",
        "services": ["dns"],
        "ports": [53],
        "poc_available": True,
        "exploit_type": "dns_poison",
        "auth_required": False,
        "references": [
            "https://nvd.nist.gov/vuln/detail/CVE-2019-3979",
            "https://www.tenable.com/security/research/tra-2019-46",
        ],
        "metasploit": None,
        "notes": "DNS cache/server must be enabled. Disable or upgrade.",
    },
    # ─────────────────────────────────────────────────────────────────────────
    # 2017 — Network Flood DoS, L2TP
    # ─────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2017-6444",
        "title": "TCP ACK Flood Denial of Service (hAP Lite)",
        "description": "TCP ACK flood causes DoS on MikroTik hAP Lite with RouterOS 6.25.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((6, 25, 0), (6, 25, 99))],
        "fixed_in": "6.26+",
        "services": ["tcp"],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-6444"],
        "metasploit": None,
        "notes": "Specific to hAP Lite / 6.25.",
    },
    {
        "cve_id": "CVE-2017-7285",
        "title": "TCP RST Flood Denial of Service",
        "description": "TCP RST flood causes DoS on RouterOS 6.38.5.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((6, 38, 5), (6, 38, 5))],
        "fixed_in": "6.38.6+",
        "services": ["tcp"],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-7285"],
        "metasploit": None,
        "notes": "Specific to 6.38.5.",
    },
    {
        "cve_id": "CVE-2017-8338",
        "title": "UDP Flood DoS (Port 500 — IKE)",
        "description": "UDP flood to port 500 causes DoS on RouterOS 6.38.5.",
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((6, 38, 5), (6, 38, 5))],
        "fixed_in": "6.38.6+",
        "services": ["ike", "ipsec"],
        "ports": [500],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-8338"],
        "metasploit": None,
        "notes": "IPsec IKE port 500 DoS.",
    },
    {
        "cve_id": "CVE-2017-6297",
        "title": "L2TP IPsec Reboot Downgrade (MitM)",
        "description": (
            "RouterOS 6.83.3 / 6.37.4 L2TP/IPsec implementation can be downgraded "
            "via MitM to cause a reboot, enabling session hijacking."
        ),
        "severity": "MEDIUM",
        "cvss_score": 5.9,
        "affected": [((6, 37, 4), (6, 83, 3))],
        "fixed_in": "Check MikroTik advisory",
        "services": ["l2tp", "ipsec"],
        "ports": [1701, 500, 4500],
        "poc_available": False,
        "exploit_type": "mitm",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-6297"],
        "metasploit": None,
        "notes": "MitM attack on L2TP/IPsec; requires network position.",
    },
    {
        "cve_id": "CVE-2022-36522",
        "title": "Netwatch Assertion Failure DoS",
        "description": "Netwatch process assertion failure causes DoS on RouterOS <= 6.48.3.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 48, 3))],
        "fixed_in": "6.48.4+",
        "services": ["netwatch"],
        "ports": [],
        "poc_available": False,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2022-36522"],
        "metasploit": None,
        "notes": "Requires authentication.",
    },
    # ──────────────────────────────────────────────────────────────────────────
    # 2020 Memory Corruption Series + Legacy CVEs (Sprint 2)
    # ──────────────────────────────────────────────────────────────────────────
    {
        "cve_id": "CVE-2020-20212",
        "title": "console NULL Pointer Dereference DoS",
        "description": "console NULL Pointer Dereference DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47 / 6.44.5 LTS",
        "services": ['console'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20212"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/console NULL deref.",
    },
    {
        "cve_id": "CVE-2020-20216",
        "title": "graphing NULL Pointer Dereference DoS",
        "description": "graphing NULL Pointer Dereference DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47 / 6.44.6 LTS",
        "services": ['graphing'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20216"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/graphing NULL deref.",
    },
    {
        "cve_id": "CVE-2020-20218",
        "title": "traceroute Memory Corruption",
        "description": "traceroute Memory Corruption on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47 / 6.44.6 LTS",
        "services": ['traceroute'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20218"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/traceroute memcorrupt.",
    },
    {
        "cve_id": "CVE-2020-20219",
        "title": "igmp-proxy NULL Pointer Dereference DoS",
        "description": "igmp-proxy NULL Pointer Dereference DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47",
        "services": ['igmp-proxy'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20219"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/igmp-proxy NULL deref.",
    },
    {
        "cve_id": "CVE-2020-20220",
        "title": "bfd NULL Pointer Dereference DoS",
        "description": "bfd NULL Pointer Dereference DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47",
        "services": ['bfd'],
        "ports": [3784, 3785],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20220"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/bfd NULL deref.",
    },
    {
        "cve_id": "CVE-2020-20222",
        "title": "sniffer NULL Pointer Dereference DoS",
        "description": "sniffer NULL Pointer Dereference DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47 / 6.44.6 LTS",
        "services": ['sniffer'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20222"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/sniffer NULL deref.",
    },
    {
        "cve_id": "CVE-2020-20227",
        "title": "diskd Memory Corruption",
        "description": "diskd Memory Corruption on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [((6, 47, 0), (6, 47, 0))],
        "fixed_in": "6.47.1+",
        "services": ['disk'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20227"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/diskd memcorrupt.",
    },
    {
        "cve_id": "CVE-2020-20231",
        "title": "detnet NULL Pointer Dereference DoS",
        "description": "detnet NULL Pointer Dereference DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 48, 3))],
        "fixed_in": "6.48.4+",
        "services": ['detnet'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20231"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/detnet NULL deref.",
    },
    {
        "cve_id": "CVE-2020-20236",
        "title": "sniffer Memory Corruption (v2)",
        "description": "sniffer Memory Corruption (v2) on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [((6, 46, 3), (6, 46, 3))],
        "fixed_in": "6.46.4+",
        "services": ['sniffer'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20236"],
        "metasploit": None,
        "notes": "Authenticated; sniffer memcorrupt on 6.46.3.",
    },
    {
        "cve_id": "CVE-2020-20237",
        "title": "sniffer Memory Corruption (v3)",
        "description": "sniffer Memory Corruption (v3) on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [((6, 46, 3), (6, 46, 3))],
        "fixed_in": "6.46.4+",
        "services": ['sniffer'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20237"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/sniffer memcorrupt on 6.46.3.",
    },
    {
        "cve_id": "CVE-2020-20245",
        "title": "log Process OOB Write",
        "description": "log Process OOB Write on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [((6, 46, 3), (6, 46, 3))],
        "fixed_in": "6.46.4+",
        "services": ['log'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20245"],
        "metasploit": None,
        "notes": "Authenticated; log process out-of-bounds write.",
    },
    {
        "cve_id": "CVE-2020-20246",
        "title": "mactel Process OOB Write",
        "description": "mactel Process OOB Write on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [((6, 46, 3), (6, 46, 3))],
        "fixed_in": "6.46.4+",
        "services": ['mac-telnet'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20246"],
        "metasploit": None,
        "notes": "Authenticated; mactel process out-of-bounds write.",
    },
    {
        "cve_id": "CVE-2020-20247",
        "title": "traceroute Memory Corruption (v2)",
        "description": "traceroute Memory Corruption (v2) on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ['traceroute'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20247"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/traceroute memcorrupt.",
    },
    {
        "cve_id": "CVE-2020-20249",
        "title": "resolver Memory Corruption",
        "description": "resolver Memory Corruption on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ['dns'],
        "ports": [53],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20249"],
        "metasploit": None,
        "notes": "Authenticated; resolver memcorrupt.",
    },
    {
        "cve_id": "CVE-2020-20250",
        "title": "lcdstat NULL Pointer Dereference DoS",
        "description": "lcdstat NULL Pointer Dereference DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ['lcd'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20250"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/lcdstat NULL deref.",
    },
    {
        "cve_id": "CVE-2020-20252",
        "title": "lcdstat NULL Pointer Dereference DoS (v2)",
        "description": "lcdstat NULL Pointer Dereference DoS (v2) on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ['lcd'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20252"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/lcdstat NULL deref variant.",
    },
    {
        "cve_id": "CVE-2020-20254",
        "title": "lcdstat NULL Pointer Dereference DoS (v3)",
        "description": "lcdstat NULL Pointer Dereference DoS (v3) on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ['lcd'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20254"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/lcdstat NULL deref variant.",
    },
    {
        "cve_id": "CVE-2020-20264",
        "title": "netwatch Divide-by-Zero DoS",
        "description": "netwatch Divide-by-Zero DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ['netwatch'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20264"],
        "metasploit": None,
        "notes": "Authenticated; netwatch divide-by-zero.",
    },
    {
        "cve_id": "CVE-2020-20265",
        "title": "wireless Process Memory Corruption",
        "description": "wireless Process Memory Corruption on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ['wireless'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20265"],
        "metasploit": None,
        "notes": "Authenticated; wireless process memcorrupt.",
    },
    {
        "cve_id": "CVE-2020-20266",
        "title": "dot1x NULL Pointer Dereference DoS",
        "description": "dot1x NULL Pointer Dereference DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ['dot1x', '802.1x'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20266"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/dot1x NULL deref.",
    },
    {
        "cve_id": "CVE-2020-20267",
        "title": "resolver Memory Corruption (v2)",
        "description": "resolver Memory Corruption (v2) on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.5,
        "affected": [(None, (6, 46, 99))],
        "fixed_in": "6.47+",
        "services": ['dns'],
        "ports": [53],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": True,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-20267"],
        "metasploit": None,
        "notes": "Authenticated; /nova/bin/resolver memcorrupt.",
    },
    {
        "cve_id": "CVE-2017-17537",
        "title": "RouterBOARD DNS TCP DoS",
        "description": "RouterBOARD DNS TCP DoS on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected": [((6, 39, 2), (6, 40, 5))],
        "fixed_in": "6.40.6+",
        "services": ['dns'],
        "ports": [53],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-17537"],
        "metasploit": None,
        "notes": "DNS TCP DoS on 6.39.2 / 6.40.5.",
    },
    {
        "cve_id": "CVE-2017-17538",
        "title": "ICMP Flood DoS (6.40.5)",
        "description": "ICMP Flood DoS (6.40.5) on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 5.3,
        "affected": [((6, 40, 5), (6, 40, 5))],
        "fixed_in": "6.40.6+",
        "services": ['icmp'],
        "ports": [],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2017-17538"],
        "metasploit": None,
        "notes": "ICMP flood on 6.40.5.",
    },
    {
        "cve_id": "CVE-2015-2350",
        "title": "CSRF Admin Password Change",
        "description": "CSRF Admin Password Change on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.8,
        "affected": [(None, (5, 0, 99))],
        "fixed_in": "5.1+",
        "services": ['http', 'webfig'],
        "ports": [80],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2015-2350"],
        "metasploit": None,
        "notes": "CSRF attack on very old RouterOS <= 5.0.",
    },
    {
        "cve_id": "CVE-2012-6050",
        "title": "Winbox DoS + Version Leak",
        "description": "Winbox DoS + Version Leak on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.4,
        "affected": [(None, (5, 15, 99))],
        "fixed_in": "5.16+",
        "services": ['winbox'],
        "ports": [8291],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2012-6050"],
        "metasploit": None,
        "notes": "Very old; Winbox DoS and version info disclosure.",
    },
    {
        "cve_id": "CVE-2008-6976",
        "title": "SNMP NMS Config Modification",
        "description": "SNMP NMS Config Modification on MikroTik RouterOS.",
        "severity": "MEDIUM",
        "cvss_score": 6.4,
        "affected": [((2, 0, 0), (3, 13, 99))],
        "fixed_in": "3.14+",
        "services": ['snmp'],
        "ports": [161],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2008-6976"],
        "metasploit": None,
        "notes": "Same as EDB-6366; SNMP SET allowed on read-only interface.",
    },
]


def _parse_version(version_str: str) -> VersionTuple:
    """Parse a version string into a comparable tuple."""
    try:
        return tuple(int(x) for x in str(version_str).split(".")[:3])
    except (ValueError, AttributeError):
        return (0,)


def _in_range(ver: VersionTuple, affected_range: Tuple) -> bool:
    """Check if a version tuple falls within an affected range.

    Args:
        ver: Parsed version tuple.
        affected_range: Tuple of (min_ver, max_ver), where None means unbounded.
    """
    min_ver, max_ver = affected_range
    if min_ver is not None and ver < tuple(min_ver):
        return False
    if max_ver is not None and ver > tuple(max_ver):
        return False
    return True


def get_cves_for_version(version: str) -> List[Dict]:
    """Return CVEs applicable to the given RouterOS version.

    Args:
        version: RouterOS version string, e.g. '7.20.7' or '6.49.6 (stable)'.

    Returns:
        List of CVE dicts applicable to the specified version.
    """
    # Strip parenthetical qualifiers like '(long-term)' or '(stable)'
    clean = version.split(" ")[0].strip()
    ver = _parse_version(clean)

    applicable = []
    for cve in CVE_DATABASE:
        # Config/design findings: apply range check normally (not auto-include)
        for affected_range in cve["affected"]:
            if _in_range(ver, affected_range):
                applicable.append(cve)
                break

    return applicable


def get_all_cves() -> List[Dict]:
    """Return the complete CVE database."""
    return CVE_DATABASE


def get_cves_by_severity(severity: str) -> List[Dict]:
    """Return CVEs filtered by severity level.

    Args:
        severity: One of 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'.
    """
    return [c for c in CVE_DATABASE if c["severity"].upper() == severity.upper()]


def get_cves_with_poc() -> List[Dict]:
    """Return only CVEs that have public PoC implementations."""
    return [c for c in CVE_DATABASE if c["poc_available"]]


def get_cves_by_service(service: str) -> List[Dict]:
    """Return CVEs that target a specific service.

    Args:
        service: Service name e.g. 'winbox', 'smb', 'http', 'api'.
    """
    return [c for c in CVE_DATABASE if service.lower() in c.get("services", [])]


def get_cves_preauth() -> List[Dict]:
    """Return only pre-authentication CVEs (no credentials needed)."""
    return [c for c in CVE_DATABASE if not c.get("auth_required", True)]


def print_cve_summary() -> None:
    """Print a formatted summary of the CVE database."""
    print(f"\n{'='*70}")
    print(f"  MikrotikAPI-BF CVE Database — {len(CVE_DATABASE)} entries")
    print(f"{'='*70}")

    by_severity = {}
    for cve in CVE_DATABASE:
        sev = cve["severity"]
        by_severity.setdefault(sev, []).append(cve)

    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        if sev not in by_severity:
            continue
        print(f"\n  [{sev}]")
        for cve in by_severity[sev]:
            poc = "[PoC]" if cve["poc_available"] else "     "
            auth = "[auth]" if cve["auth_required"] else "[pre ]"
            print(
                f"    {poc} {auth} CVSS {cve['cvss_score']:.1f}  "
                f"{cve['cve_id']:<25}  {cve['title'][:45]}"
            )

    print(f"\n  Pre-auth CVEs: {len(get_cves_preauth())}")
    print(f"  CVEs with PoC: {len(get_cves_with_poc())}")
    print(f"  Metasploit modules: {sum(1 for c in CVE_DATABASE if c.get('metasploit'))}")
    print(f"{'='*70}\n")

