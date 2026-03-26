#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
NVD & Shodan Integration — MikrotikAPI-BF
==========================================
Fetches live CVE data from the NIST National Vulnerability Database (NVD)
and target intelligence from Shodan to enrich fingerprint and exploit
scanning results.

API keys are read from environment variables or a config.json file.
  NVD_API_KEY   – https://nvd.nist.gov/developers/request-an-api-key
  SHODAN_API_KEY – https://account.shodan.io/
"""

import json
import os
import time
from pathlib import Path
from typing import Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ---------------------------------------------------------------------- #
#  Key resolution                                                          #
# ---------------------------------------------------------------------- #

def _resolve_key(env_var: str, config_section: str, config_key: str = "api_key") -> Optional[str]:
    """
    Resolve an API key from:
    1. Environment variable *env_var*.
    2. config.json in the project root (same structure as PrinterReaper).
    """
    # 1. Environment variable
    val = os.environ.get(env_var)
    if val:
        return val

    # 2. config.json in CWD or project root
    for base in (Path.cwd(), Path(__file__).parent.parent):
        cfg_path = base / "config.json"
        if cfg_path.exists():
            try:
                with open(cfg_path, "r", encoding="utf-8") as fh:
                    cfg = json.load(fh)
                entries = cfg.get(config_section, [])
                for entry in entries:
                    key = entry.get(config_key, "")
                    if key:
                        return key
            except Exception:
                pass

    return None


NVD_API_KEY = _resolve_key("NVD_API_KEY", "nvd")
SHODAN_API_KEY = _resolve_key("SHODAN_API_KEY", "shodan")


# ---------------------------------------------------------------------- #
#  NVD Client                                                              #
# ---------------------------------------------------------------------- #

class NVDClient:
    """
    Query the NIST NVD API v2 for CVE data related to MikroTik RouterOS.

    Args:
        api_key:    NVD API key (optional, raises rate limit to 50 req/30 s).
        timeout:    HTTP request timeout.
    """

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    RATE_DELAY = 6.0   # seconds between requests without API key (5 req/30 s)
    RATE_DELAY_KEY = 0.6  # with API key

    def __init__(self, api_key: Optional[str] = None, timeout: int = 15) -> None:
        self.api_key = api_key or NVD_API_KEY
        self.timeout = timeout
        self._last_request = 0.0

    def _headers(self) -> Dict[str, str]:
        h = {"Accept": "application/json"}
        if self.api_key:
            h["apiKey"] = self.api_key
        return h

    def _rate_wait(self) -> None:
        delay = self.RATE_DELAY_KEY if self.api_key else self.RATE_DELAY
        elapsed = time.time() - self._last_request
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last_request = time.time()

    def search_mikrotik_cves(
        self,
        keyword: str = "MikroTik RouterOS",
        max_results: int = 50,
    ) -> List[Dict]:
        """
        Search NVD for CVEs matching *keyword*.

        Args:
            keyword:     Search keyword.
            max_results: Maximum number of CVEs to return.

        Returns:
            List of simplified CVE dicts.
        """
        results: List[Dict] = []
        start_index = 0
        results_per_page = min(max_results, 2000)

        while len(results) < max_results:
            self._rate_wait()
            params = {
                "keywordSearch": keyword,
                "startIndex": start_index,
                "resultsPerPage": results_per_page,
            }
            try:
                resp = requests.get(
                    self.BASE_URL,
                    params=params,
                    headers=self._headers(),
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                data = resp.json()
            except Exception as exc:
                print(f"  [!] NVD API error: {exc}")
                break

            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                break

            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                results.append(self._parse_cve(cve_data))
                if len(results) >= max_results:
                    break

            total = data.get("totalResults", 0)
            start_index += len(vulnerabilities)
            if start_index >= total:
                break

        return results

    def get_cve_details(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch details for a specific CVE by ID.

        Args:
            cve_id: CVE identifier, e.g. ``"CVE-2018-14847"``.

        Returns:
            Simplified CVE dict or ``None`` on failure.
        """
        self._rate_wait()
        try:
            resp = requests.get(
                self.BASE_URL,
                params={"cveId": cve_id},
                headers=self._headers(),
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return self._parse_cve(vulns[0].get("cve", {}))
        except Exception as exc:
            print(f"  [!] NVD lookup error for {cve_id}: {exc}")
        return None

    @staticmethod
    def _parse_cve(cve_data: Dict) -> Dict:
        """Extract key fields from a raw NVD CVE response."""
        cve_id = cve_data.get("id", "Unknown")

        # Description
        descs = cve_data.get("descriptions", [])
        description = next(
            (d["value"] for d in descs if d.get("lang") == "en"), "No description available."
        )

        # CVSS score (prefer v3.1 > v3.0 > v2.0)
        cvss_score: Optional[float] = None
        severity = "UNKNOWN"
        metrics = cve_data.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                data_m = entries[0].get("cvssData", {})
                cvss_score = data_m.get("baseScore")
                severity = data_m.get("baseSeverity", entries[0].get("baseSeverity", "UNKNOWN"))
                break

        # References
        refs = [r["url"] for r in cve_data.get("references", []) if r.get("url")]

        # Published / modified dates
        published = cve_data.get("published", "")[:10]
        modified = cve_data.get("lastModified", "")[:10]

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "published": published,
            "modified": modified,
            "references": refs[:5],  # limit to 5
        }


# ---------------------------------------------------------------------- #
#  Shodan Client                                                           #
# ---------------------------------------------------------------------- #

class ShodanClient:
    """
    Query Shodan for intelligence about a specific IP address.

    Args:
        api_key: Shodan API key.
        timeout: HTTP request timeout.
    """

    BASE_URL = "https://api.shodan.io"

    def __init__(self, api_key: Optional[str] = None, timeout: int = 15) -> None:
        self.api_key = api_key or SHODAN_API_KEY
        self.timeout = timeout

    def host_info(self, ip: str) -> Dict:
        """
        Fetch Shodan intelligence for a specific IP.

        Args:
            ip: Target IPv4 address.

        Returns:
            Simplified dict with host information, or empty dict on failure.
        """
        if not self.api_key:
            return {"error": "No Shodan API key configured"}

        try:
            resp = requests.get(
                f"{self.BASE_URL}/shodan/host/{ip}",
                params={"key": self.api_key},
                timeout=self.timeout,
            )
            if resp.status_code == 404:
                return {"error": "IP not found in Shodan"}
            resp.raise_for_status()
            data = resp.json()
            return self._parse_host(data)
        except Exception as exc:
            return {"error": str(exc)}

    def search_mikrotik(self, query: str = "product:MikroTik", limit: int = 10) -> List[Dict]:
        """
        Search Shodan for MikroTik devices matching *query*.

        Args:
            query: Shodan search query.
            limit: Maximum results.

        Returns:
            List of simplified host dicts.
        """
        if not self.api_key:
            return [{"error": "No Shodan API key configured"}]
        try:
            resp = requests.get(
                f"{self.BASE_URL}/shodan/host/search",
                params={"key": self.api_key, "query": query},
                timeout=self.timeout,
            )
            resp.raise_for_status()
            data = resp.json()
            matches = data.get("matches", [])[:limit]
            return [self._parse_match(m) for m in matches]
        except Exception as exc:
            return [{"error": str(exc)}]

    @staticmethod
    def _parse_host(data: Dict) -> Dict:
        return {
            "ip": data.get("ip_str"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "org": data.get("org"),
            "isp": data.get("isp"),
            "hostnames": data.get("hostnames", []),
            "open_ports": data.get("ports", []),
            "os": data.get("os"),
            "tags": data.get("tags", []),
            "vulns": data.get("vulns", []),
            "last_update": data.get("last_update"),
            "banners": [
                {
                    "port": s.get("port"),
                    "transport": s.get("transport", "tcp"),
                    "product": s.get("product"),
                    "version": s.get("version"),
                    "banner": str(s.get("data", ""))[:200],
                }
                for s in data.get("data", [])[:10]
            ],
        }

    @staticmethod
    def _parse_match(data: Dict) -> Dict:
        return {
            "ip": data.get("ip_str"),
            "port": data.get("port"),
            "product": data.get("product"),
            "version": data.get("version"),
            "org": data.get("org"),
            "country": data.get("location", {}).get("country_name"),
            "banner": str(data.get("data", ""))[:200],
        }
