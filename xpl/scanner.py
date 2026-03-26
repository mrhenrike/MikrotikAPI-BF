"""MikroTik exploit scanner — orchestrates fingerprint, CVE match, NVD/Shodan, PoC.

Supports two display modes:
  - version-aware: only CVEs applicable to the detected RouterOS version
  - all:           all CVEs regardless of version (for training/research)

Author: André Henrique (LinkedIn/X: @mrhenrike)
Version: 3.1.0
"""
import logging
from typing import Dict, List, Optional

from .cve_db import (
    CVE_DATABASE,
    get_cves_for_version,
    get_all_cves,
    print_cve_summary,
)
from .exploits import EXPLOIT_REGISTRY
from .nvd_shodan import NVDClient, ShodanClient

log = logging.getLogger(__name__)

# ANSI color codes
_RED = "\033[91m"
_YEL = "\033[93m"
_GRN = "\033[92m"
_CYN = "\033[96m"
_MAG = "\033[95m"
_WHT = "\033[97m"
_DIM = "\033[2m"
_RST = "\033[0m"
_BLD = "\033[1m"

_SEVERITY_COLOR = {
    "CRITICAL": _RED,
    "HIGH": _YEL,
    "MEDIUM": _CYN,
    "LOW": _GRN,
}


class ExploitScanner:
    """Orchestrates version-aware or full CVE scanning against a MikroTik target.

    Args:
        show_all: If True, display all CVEs regardless of version applicability.
        username: Admin username for authenticated PoC checks.
        password: Admin password for authenticated PoC checks.
        timeout: Connection timeout for socket/HTTP operations.
    """

    def __init__(
        self,
        show_all: bool = False,
        username: str = "",
        password: str = "",
        timeout: int = 10,
    ) -> None:
        self.show_all = show_all
        self.username = username
        self.password = password
        self.timeout = timeout

    def _fingerprint_version(self, target: str) -> Optional[str]:
        """Attempt to detect RouterOS version via REST API or FTP banner."""
        # Try REST API
        try:
            import requests
            import urllib3
            urllib3.disable_warnings()
            r = requests.get(
                f"http://{target}/rest/system/resource",
                auth=(self.username, self.password) if self.username else None,
                timeout=self.timeout,
                verify=False,
            )
            if r.status_code == 200:
                data = r.json()
                version = data.get("version", "")
                if version:
                    log.info("Version detected via REST API: %s", version)
                    return version.split(" ")[0]
        except Exception as e:
            log.debug("REST API version detection failed: %s", e)

        # Fallback: FTP banner
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(self.timeout)
            s.connect((target, 21))
            banner = s.recv(256).decode("utf-8", errors="replace")
            s.close()
            # e.g. "220 MikroTik FTP server (MikroTik 7.20.7) ready"
            import re
            m = re.search(r"MikroTik\s+([\d.]+)", banner)
            if m:
                log.info("Version detected via FTP banner: %s", m.group(1))
                return m.group(1)
        except Exception as e:
            log.debug("FTP version detection failed: %s", e)

        return None

    def scan_target(
        self,
        target: str,
        version: Optional[str] = None,
        run_pocs: bool = True,
        enrich_nvd: bool = True,
        enrich_shodan: bool = True,
    ) -> Dict:
        """Run a complete exploit scan against the target.

        Args:
            target: Target IP address or hostname.
            version: RouterOS version string. Auto-detected if None.
            run_pocs: Whether to execute PoC checks.
            enrich_nvd: Whether to query NVD API for live CVE data.
            enrich_shodan: Whether to query Shodan for host intelligence.

        Returns:
            Complete scan results dict.
        """
        import datetime

        log.info("Starting exploit scan for %s", target)

        # Version detection
        if not version:
            version = self._fingerprint_version(target)
            if not version:
                log.warning("Could not auto-detect version — using 'unknown'")
                version = "unknown"

        # CVE selection
        if self.show_all or version == "unknown":
            cves = get_all_cves()
            version_note = "ALL CVEs (show_all mode or unknown version)"
        else:
            cves = get_cves_for_version(version)
            version_note = f"CVEs applicable to RouterOS {version}"

        log.info("Selected %d CVEs (%s)", len(cves), version_note)

        # NVD enrichment
        nvd_data = {}
        if enrich_nvd:
            try:
                nvd = NVDClient()
                nvd_results = nvd.search_cves(keyword="MikroTik RouterOS", results_per_page=10)
                nvd_data = {"results": nvd_results, "count": len(nvd_results)}
                log.info("NVD: %d CVEs fetched", len(nvd_results))
            except Exception as e:
                log.debug("NVD enrichment failed: %s", e)

        # Shodan intelligence
        shodan_data = {}
        if enrich_shodan:
            try:
                shodan = ShodanClient()
                shodan_data = shodan.host_info(target)
                log.info("Shodan: host info retrieved for %s", target)
            except Exception as e:
                log.debug("Shodan enrichment failed: %s", e)

        # PoC execution
        poc_results = []
        if run_pocs:
            for cve in cves:
                cve_id = cve["cve_id"]
                exploit_class = EXPLOIT_REGISTRY.get(cve_id)
                if not exploit_class:
                    continue
                try:
                    exploit = exploit_class(
                        target=target,
                        timeout=self.timeout,
                        username=self.username,
                        password=self.password,
                    )
                    result = exploit.check()
                    poc_results.append(result)
                    log.info(
                        "PoC %s: vulnerable=%s",
                        cve_id,
                        result.get("vulnerable"),
                    )
                except Exception as e:
                    poc_results.append({
                        "cve": cve_id,
                        "vulnerable": False,
                        "evidence": "",
                        "error": str(e),
                    })

        return {
            "target": target,
            "version": version,
            "version_note": version_note,
            "cves": cves,
            "cve_count": len(cves),
            "nvd_data": nvd_data,
            "shodan": shodan_data,
            "poc_results": poc_results,
            "timestamp": datetime.datetime.utcnow().isoformat(),
        }

    def print_results(self, results: Dict) -> None:
        """Print formatted scan results to stdout.

        Args:
            results: Dict returned by scan_target().
        """
        target = results.get("target", "")
        version = results.get("version", "?")
        cves = results.get("cves", [])
        poc_results = results.get("poc_results", [])
        shodan = results.get("shodan", {})
        nvd = results.get("nvd_data", {})

        # Build PoC result lookup
        poc_map: Dict[str, Dict] = {p.get("cve", ""): p for p in poc_results}

        print(f"\n{_BLD}{'='*70}{_RST}")
        print(f"{_BLD}  EXPLOIT SCAN RESULTS — {target} — RouterOS {version}{_RST}")
        print(f"{_BLD}{'='*70}{_RST}")
        print(f"  {_DIM}Mode: {results.get('version_note', '')}{_RST}")

        # Shodan summary
        if shodan and shodan.get("ip"):
            print(f"\n  {_CYN}[SHODAN]{_RST}")
            print(f"    IP      : {shodan.get('ip')}")
            print(f"    Org     : {shodan.get('org', 'N/A')}")
            print(f"    Country : {shodan.get('country', 'N/A')}")
            ports = shodan.get("ports", [])
            if ports:
                print(f"    Ports   : {', '.join(str(p) for p in sorted(ports))}")
            vulns = shodan.get("vulns", [])
            if vulns:
                print(f"    Vulns   : {', '.join(vulns[:5])}")

        # CVE list
        print(f"\n  {_BLD}CVE DATABASE ({len(cves)} entries){_RST}")
        print(f"  {'CVE ID':<28} {'SEV':<8} {'CVSS':<6} {'PoC':<6} {'AUTH':<6} {'STATUS'}")
        print(f"  {'-'*28} {'-'*8} {'-'*6} {'-'*6} {'-'*6} {'-'*20}")

        for cve in cves:
            cve_id = cve["cve_id"]
            severity = cve.get("severity", "UNKNOWN")
            cvss = cve.get("cvss_score", 0.0)
            poc_flag = "[PoC]" if cve.get("poc_available") else "     "
            auth_flag = "[auth]" if cve.get("auth_required") else "[pre ]"
            color = _SEVERITY_COLOR.get(severity, _WHT)

            # PoC result
            poc_r = poc_map.get(cve_id)
            if poc_r:
                if poc_r.get("vulnerable"):
                    status = f"{_RED}VULNERABLE{_RST}"
                elif poc_r.get("error"):
                    status = f"{_DIM}ERROR: {poc_r['error'][:30]}{_RST}"
                else:
                    status = f"{_GRN}NOT VULNERABLE{_RST}"
            else:
                status = f"{_DIM}(no PoC impl){_RST}"

            print(
                f"  {color}{cve_id:<28}{_RST} "
                f"{color}{severity:<8}{_RST} "
                f"{cvss:<6.1f} "
                f"{poc_flag} "
                f"{auth_flag} "
                f"{status}"
            )

        # Vulnerable findings
        vulns_found = [p for p in poc_results if p.get("vulnerable")]
        if vulns_found:
            print(f"\n  {_RED}{_BLD}CONFIRMED VULNERABILITIES ({len(vulns_found)}){_RST}")
            for v in vulns_found:
                print(f"\n  {_RED}[VULN]{_RST} {_BLD}{v['cve']}{_RST}")
                print(f"         {v.get('evidence', '')[:120]}")

        # NVD summary
        nvd_count = nvd.get("count", 0)
        if nvd_count:
            print(f"\n  {_CYN}[NVD] {nvd_count} live CVEs fetched for 'MikroTik RouterOS'{_RST}")

        print(f"\n{_BLD}{'='*70}{_RST}\n")

    def list_all_cves(self) -> None:
        """Print the full CVE database summary."""
        print_cve_summary()
        for cve in get_all_cves():
            sev_color = _SEVERITY_COLOR.get(cve.get("severity", ""), _WHT)
            poc = "[PoC]" if cve.get("poc_available") else "     "
            auth = "[auth]" if cve.get("auth_required") else "[pre ]"
            print(
                f"  {sev_color}{cve['cve_id']:<28}{_RST} "
                f"CVSS {cve.get('cvss_score', 0):.1f}  "
                f"{poc} {auth}  "
                f"{cve.get('title', '')[:55]}"
            )
            if cve.get("metasploit"):
                print(f"    {_DIM}Metasploit: {cve['metasploit']}{_RST}")
            refs = cve.get("references", [])[:2]
            for ref in refs:
                print(f"    {_DIM}{ref}{_RST}")
