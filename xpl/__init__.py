"""xpl — MikroTik RouterOS exploit and CVE scanning package.

Provides:
  - CVE_DATABASE: complete curated MikroTik CVE database (17+ entries)
  - get_cves_for_version(): version-aware CVE filter
  - get_all_cves(): full database regardless of version
  - get_cves_with_poc(): only CVEs with public PoC
  - get_cves_preauth(): pre-authentication CVEs only
  - get_cves_by_severity(): filter by severity level
  - get_cves_by_service(): filter by service (winbox, smb, http, api...)
  - ExploitScanner: orchestrates fingerprint + CVE match + NVD/Shodan + PoC
  - EXPLOIT_REGISTRY: maps CVE IDs to PoC exploit classes

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 3.1.0
"""
from .cve_db import (
    CVE_DATABASE,
    get_cves_for_version,
    get_all_cves,
    get_cves_by_severity,
    get_cves_with_poc,
    get_cves_by_service,
    get_cves_preauth,
    print_cve_summary,
)
from .exploits import EXPLOIT_REGISTRY
from .scanner import ExploitScanner

__all__ = [
    "CVE_DATABASE",
    "get_cves_for_version",
    "get_all_cves",
    "get_cves_by_severity",
    "get_cves_with_poc",
    "get_cves_by_service",
    "get_cves_preauth",
    "print_cve_summary",
    "EXPLOIT_REGISTRY",
    "ExploitScanner",
]
