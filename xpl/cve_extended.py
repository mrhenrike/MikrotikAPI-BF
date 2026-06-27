"""Extended MikroTik CVE entries merged into CVE_DATABASE at import."""
from typing import Dict, List

EXTENDED_CVE_ENTRIES: List[Dict] = [
    {
        "cve_id": "CVE-2024-27686",
        "title": "RouterOS SMB Denial of Service",
        "description": (
            "Crafted SMB packets crash the RouterOS SMB service on versions "
            "6.40.5–6.44 and 6.48.1–6.49.10 (EDB-51931)."
        ),
        "severity": "HIGH",
        "cvss_score": 7.5,
        "affected": [((6, 40, 5), (6, 44, 99)), ((6, 48, 1), (6, 49, 10))],
        "fixed_in": "6.44.1 / 6.49.11",
        "services": ["smb"],
        "ports": [445],
        "poc_available": True,
        "exploit_type": "dos",
        "auth_required": False,
        "references": [
            "https://www.exploit-db.com/exploits/51931",
            "https://nvd.nist.gov/vuln/detail/CVE-2024-27686",
        ],
        "metasploit": None,
        "notes": "Native PoC in xpl/poc_payloads.py (EDB-51931 packets).",
    },
]
