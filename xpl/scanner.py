#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Exploit Scanner — MikrotikAPI-BF
==================================
Orchestrates fingerprinting → CVE matching → PoC verification.

Workflow:
  1. Fingerprint the target to detect RouterOS version and services.
  2. Query the local CVE database for applicable vulnerabilities.
  3. Optionally enrich with live NVD data.
  4. Run available PoC checks against the target.
  5. Optionally collect Shodan intelligence.
  6. Return consolidated results ready for display or reporting.
"""

from datetime import datetime
from typing import Dict, List, Optional

from .cve_db import get_cves_for_version, get_all_cves
from .exploits import get_exploit, EXPLOIT_REGISTRY
from .nvd_shodan import NVDClient, ShodanClient


class ExploitScanner:
    """
    Version-aware exploit scanner for MikroTik RouterOS.

    Args:
        timeout:         Per-check timeout in seconds.
        use_nvd:         Fetch live CVE data from NVD API.
        use_shodan:      Fetch host intelligence from Shodan.
        nvd_api_key:     Optional NVD API key override.
        shodan_api_key:  Optional Shodan API key override.
    """

    def __init__(
        self,
        timeout: int = 5,
        use_nvd: bool = True,
        use_shodan: bool = True,
        nvd_api_key: Optional[str] = None,
        shodan_api_key: Optional[str] = None,
    ) -> None:
        self.timeout = timeout
        self.use_nvd = use_nvd
        self.use_shodan = use_shodan
        self._nvd = NVDClient(api_key=nvd_api_key)
        self._shodan = ShodanClient(api_key=shodan_api_key)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan_target(self, target: str, version: Optional[str] = None) -> Dict:
        """
        Perform a full exploit scan against *target*.

        Args:
            target:  Target IP address or hostname.
            version: RouterOS version string (auto-detected if ``None``).

        Returns:
            Comprehensive result dict.
        """
        print(f"\n  [XPL] Starting exploit scan: {target}")
        scan_time = datetime.now().isoformat()

        # 1. Fingerprint if version not provided
        detected_version = version
        fingerprint: Dict = {}
        if not detected_version:
            detected_version, fingerprint = self._fingerprint(target)

        print(f"  [XPL] RouterOS version: {detected_version or 'Unknown'}")

        # 2. Match CVEs
        if detected_version:
            applicable_cves = get_cves_for_version(detected_version)
        else:
            applicable_cves = get_all_cves()

        print(f"  [XPL] Applicable CVEs in local DB: {len(applicable_cves)}")

        # 3. Enrich with NVD
        nvd_data: List[Dict] = []
        if self.use_nvd:
            print("  [XPL] Querying NVD…")
            try:
                nvd_data = self._nvd.search_mikrotik_cves(max_results=20)
                print(f"  [XPL] NVD returned {len(nvd_data)} result(s)")
            except Exception as exc:
                print(f"  [!] NVD query failed: {exc}")

        # 4. Shodan intelligence
        shodan_data: Dict = {}
        if self.use_shodan:
            print("  [XPL] Querying Shodan…")
            try:
                shodan_data = self._shodan.host_info(target)
                if "error" not in shodan_data:
                    print(f"  [XPL] Shodan: {shodan_data.get('org', 'Unknown org')}, "
                          f"ports: {shodan_data.get('open_ports', [])}")
            except Exception as exc:
                print(f"  [!] Shodan query failed: {exc}")

        # 5. Run PoC checks
        poc_results: List[Dict] = []
        print(f"  [XPL] Running PoC checks ({len(EXPLOIT_REGISTRY)} available)…")
        for cve in applicable_cves:
            cve_id = cve["cve_id"]
            exploit = get_exploit(cve_id, target, self.timeout)
            if exploit:
                print(f"  [XPL] Checking {cve_id}…", end=" ", flush=True)
                result = exploit.check()
                poc_results.append(result)
                status = result.get("status", "")
                icon = "✓" if result.get("vulnerable") else "✗"
                print(f"{icon} {status}")
            else:
                poc_results.append({
                    "cve_id": cve_id,
                    "title": cve.get("title", ""),
                    "target": target,
                    "vulnerable": None,
                    "evidence": "No automated PoC available — manual check recommended",
                    "status": "MANUAL CHECK",
                })

        return {
            "target": target,
            "scan_time": scan_time,
            "routeros_version": detected_version,
            "fingerprint": fingerprint,
            "applicable_cves": applicable_cves,
            "nvd_data": nvd_data,
            "shodan": shodan_data,
            "poc_results": poc_results,
            "vulnerable_count": sum(1 for r in poc_results if r.get("vulnerable") is True),
            "total_checked": len(poc_results),
        }

    # ------------------------------------------------------------------
    # Display helpers
    # ------------------------------------------------------------------

    def print_results(self, results: Dict) -> None:
        """Pretty-print scan results to stdout."""
        target = results.get("target", "?")
        version = results.get("routeros_version", "Unknown")
        poc_results = results.get("poc_results", [])
        applicable = results.get("applicable_cves", [])
        shodan = results.get("shodan", {})

        print(f"\n{'═'*70}")
        print(f"  EXPLOIT SCAN RESULTS — {target}")
        print(f"{'═'*70}")
        print(f"  RouterOS Version : {version}")
        print(f"  Scan Time        : {results.get('scan_time', '')}")

        # Shodan summary
        if shodan and "error" not in shodan:
            print(f"\n  ── SHODAN INTELLIGENCE ──────────────────────────────")
            print(f"  Organisation : {shodan.get('org', 'N/A')}")
            print(f"  Country      : {shodan.get('country', 'N/A')}")
            print(f"  Open Ports   : {', '.join(map(str, shodan.get('open_ports', [])))}")
            if shodan.get("vulns"):
                print(f"  Shodan Vulns : {', '.join(shodan['vulns'])}")

        print(f"\n  ── CVEs APPLICABLE TO DETECTED VERSION ──────────────")
        if not applicable:
            print("  None detected.")
        for cve in applicable:
            sev = cve.get("severity", "N/A")
            score = cve.get("cvss_score", "N/A")
            poc = "✓ PoC" if cve.get("poc_available") else "  PoC N/A"
            print(f"  [{sev:<8}] [{score:>4}] {cve['cve_id']:18}  {poc}  {cve['title']}")

        print(f"\n  ── PoC CHECK RESULTS ────────────────────────────────")
        if not poc_results:
            print("  No checks run.")
        for r in poc_results:
            vuln = r.get("vulnerable")
            icon = "🔴 VULNERABLE" if vuln else ("⚫ MANUAL" if vuln is None else "🟢 NOT VULN")
            print(f"  {r['cve_id']:18}  {icon}")
            if r.get("evidence"):
                print(f"    {r['evidence']}")

        vuln_count = results.get("vulnerable_count", 0)
        total = results.get("total_checked", 0)
        print(f"\n  ── SUMMARY ─────────────────────────────────────────")
        print(f"  Vulnerable : {vuln_count}/{total} checks")
        print(f"{'═'*70}\n")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _fingerprint(self, target: str) -> tuple:
        """Return (version_str, fingerprint_dict) for the target."""
        try:
            from modules.fingerprint import MikrotikFingerprinter
            fp = MikrotikFingerprinter(timeout=self.timeout)
            info = fp.fingerprint_device(target)
            return info.get("routeros_version"), info
        except Exception:
            return None, {}
