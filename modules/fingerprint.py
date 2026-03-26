#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Device Fingerprinting Module — MikrotikAPI-BF
===============================================
Identifies Mikrotik RouterOS devices, detects the firmware version,
enumerates exposed services, and scores the attack surface risk.
"""

import re
import socket
from datetime import datetime
from typing import Dict, List, Optional

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class MikrotikFingerprinter:
    """
    Full fingerprinting of a Mikrotik RouterOS device.

    Args:
        timeout: TCP/HTTP connection timeout in seconds.
    """

    MIKROTIK_PORTS: Dict[str, int] = {
        "api": 8728,
        "api-ssl": 8729,
        "winbox": 8291,
        "http": 80,
        "https": 443,
        "ssh": 22,
        "telnet": 23,
        "ftp": 21,
        "snmp": 161,
    }

    VERSION_PATTERNS: List[str] = [
        r"RouterOS\s+v?(\d+\.\d+(?:\.\d+)?)",
        r"\"version\":\s*\"([^\"]+)\"",
        r"version=([0-9]+\.[0-9]+(?:\.[0-9]+)?)",
    ]

    def __init__(self, timeout: int = 5) -> None:
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public
    # ------------------------------------------------------------------

    def fingerprint_device(self, target: str) -> Dict:
        """
        Run a full fingerprint against *target*.

        Returns:
            Dictionary with keys: target, is_mikrotik, routeros_version,
            model, api_version, open_ports, services, vulnerabilities,
            risk_score, fingerprint_time.
        """
        info: Dict = {
            "target": target,
            "is_mikrotik": False,
            "routeros_version": None,
            "model": None,
            "api_version": None,
            "open_ports": [],
            "services": [],
            "vulnerabilities": [],
            "risk_score": 0.0,
            "fingerprint_time": datetime.now().isoformat(),
        }

        open_ports = self._scan_ports(target)
        info["open_ports"] = open_ports

        if not open_ports:
            return info

        services = self._detect_services(target, open_ports)
        info["services"] = services

        if self._is_mikrotik(target, services):
            info["is_mikrotik"] = True
            info.update(self._get_details(target, services))
            info["vulnerabilities"] = self._assess_vulnerabilities(info)
            info["risk_score"] = self._risk_score(info)

        return info

    def generate_report(self, info: Dict) -> str:
        """Return a human-readable fingerprint report."""
        vulns = "\n".join(f"  - {v}" for v in info.get("vulnerabilities", []))
        return (
            f"\n{'='*60}\n"
            f"MIKROTIK FINGERPRINT REPORT\n"
            f"{'='*60}\n"
            f"Target          : {info.get('target')}\n"
            f"Fingerprint Time: {info.get('fingerprint_time')}\n"
            f"Is Mikrotik     : {'YES' if info.get('is_mikrotik') else 'NO'}\n\n"
            f"RouterOS Version: {info.get('routeros_version', 'Unknown')}\n"
            f"Model           : {info.get('model', 'Unknown')}\n"
            f"API Version     : {info.get('api_version', 'Unknown')}\n\n"
            f"Open Ports      : {', '.join(map(str, info.get('open_ports', [])))}\n"
            f"Services        : {', '.join(info.get('services', []))}\n\n"
            f"Vulnerabilities :\n{vulns or '  None detected'}\n\n"
            f"Risk Score      : {info.get('risk_score', 0):.1f}/10\n"
            f"{'='*60}\n"
        )

    # ------------------------------------------------------------------
    # Port / service detection
    # ------------------------------------------------------------------

    def _scan_ports(self, target: str) -> List[int]:
        open_ports: List[int] = []
        for _svc, port in self.MIKROTIK_PORTS.items():
            if self._tcp_open(target, port):
                open_ports.append(port)
        return open_ports

    def _tcp_open(self, target: str, port: int) -> bool:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(self.timeout)
                return s.connect_ex((target, port)) == 0
        except Exception:
            return False

    def _detect_services(self, target: str, open_ports: List[int]) -> List[str]:
        port_map = {v: k for k, v in self.MIKROTIK_PORTS.items()}
        services: List[str] = []
        for port in open_ports:
            svc = port_map.get(port)
            if svc and self._verify_service(target, port, svc):
                services.append(svc)
        return services

    def _verify_service(self, target: str, port: int, service: str) -> bool:
        try:
            if service in ("http", "https"):
                proto = "https" if port == 443 else "http"
                resp = requests.get(
                    f"{proto}://{target}:{port}",
                    timeout=self.timeout,
                    verify=False,
                    allow_redirects=True,
                )
                text = resp.text.lower()
                return "mikrotik" in text or "routeros" in text or "webfig" in text
            if service == "api":
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(self.timeout)
                sock.connect((target, port))
                sock.close()
                return True
            # winbox, ssh, ftp, telnet — port open is sufficient
            return True
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Mikrotik identification
    # ------------------------------------------------------------------

    def _is_mikrotik(self, target: str, services: List[str]) -> bool:
        # API / Winbox ports are strong indicators
        if any(s in services for s in ("api", "api-ssl", "winbox")):
            return True
        # Fall back to HTTP banner check
        try:
            resp = requests.get(
                f"http://{target}", timeout=self.timeout, verify=False, allow_redirects=True
            )
            text = resp.text.lower()
            return "mikrotik" in text or "routeros" in text or "webfig" in text
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Details
    # ------------------------------------------------------------------

    def _get_details(self, target: str, services: List[str]) -> Dict:
        details: Dict = {}

        # Try RouterOS version via HTTP banner
        if "http" in services or "https" in services:
            ver = self._version_from_http(target)
            if ver:
                details["routeros_version"] = ver
            model = self._model_from_http(target)
            if model:
                details["model"] = model

        # Try via API if HTTP didn't give us a version
        if not details.get("routeros_version") and "api" in services:
            ver = self._version_from_api(target)
            if ver:
                details["routeros_version"] = ver

        return details

    def _version_from_http(self, target: str) -> Optional[str]:
        for proto, port in (("http", 80), ("https", 443)):
            try:
                resp = requests.get(
                    f"{proto}://{target}:{port}",
                    timeout=self.timeout,
                    verify=False,
                )
                for pattern in self.VERSION_PATTERNS:
                    m = re.search(pattern, resp.text, re.IGNORECASE)
                    if m:
                        return m.group(1)
            except Exception:
                continue
        return None

    def _model_from_http(self, target: str) -> Optional[str]:
        model_patterns = [r"RB(\w+)", r"RouterBoard\s+(\w+)", r"CHR", r"CCR\d+"]
        try:
            resp = requests.get(f"http://{target}", timeout=self.timeout, verify=False)
            for pattern in model_patterns:
                m = re.search(pattern, resp.text, re.IGNORECASE)
                if m:
                    return m.group(0)
        except Exception:
            pass
        return None

    def _version_from_api(self, target: str) -> Optional[str]:
        """Connect to API port 8728 and attempt to read the version."""
        try:
            from core.api import Api
            api = Api(target, 8728)
            api.connect()
            # Send /system/resource/print without auth — some versions leak version
            api.send(["/system/resource/print"])
            sentence = api.read_sentence()
            api.disconnect()
            for word in sentence:
                if "version" in word.lower():
                    _, _, ver = word.partition("=")
                    return ver or None
        except Exception:
            pass
        return None

    # ------------------------------------------------------------------
    # Vulnerability assessment
    # ------------------------------------------------------------------

    def _assess_vulnerabilities(self, info: Dict) -> List[str]:
        vulns: List[str] = []
        services = info.get("services", [])

        if "telnet" in services:
            vulns.append("Telnet enabled (plaintext protocol — CVE-class risk)")
        if "ftp" in services:
            vulns.append("FTP enabled (plaintext credentials in transit)")
        if "winbox" in services:
            vulns.append("Winbox exposed (CVE-2018-14847 — credential disclosure in old firmware)")
        if "api" in services:
            vulns.append("RouterOS API exposed — brute-force / CVE-2019-3924 risk")
        if "http" in services and "https" not in services:
            vulns.append("HTTP WebFig without TLS (credentials sent in plaintext)")
        if "snmp" in services:
            vulns.append("SNMP exposed — information disclosure risk")

        ver = info.get("routeros_version")
        if ver:
            vulns.extend(self._version_vulns(ver))

        return vulns

    @staticmethod
    def _version_vulns(version: str) -> List[str]:
        """Return known CVEs based on the detected version string."""
        vulns: List[str] = []
        try:
            major, minor = (int(x) for x in version.split(".")[:2])
        except Exception:
            return vulns

        if major == 6 and minor < 42:
            vulns.append(f"RouterOS {version} — CVE-2018-14847 (Winbox credential disclosure)")
        if major == 6 and minor < 43:
            vulns.append(f"RouterOS {version} — CVE-2019-3943 (path traversal)")
        if major == 6 and (minor < 49 or (minor == 49 and len(version.split(".")) > 2 and int(version.split(".")[2]) < 8)):
            vulns.append(f"RouterOS {version} — CVE-2023-30799 (privilege escalation via supout.rif)")
        if major == 7 and minor < 10:
            vulns.append(f"RouterOS {version} — CVE-2023-30799 (privilege escalation via supout.rif)")

        return vulns

    # ------------------------------------------------------------------
    # Risk scoring
    # ------------------------------------------------------------------

    def _risk_score(self, info: Dict) -> float:
        score = 2.0 if info.get("is_mikrotik") else 0.0
        high_risk = {"telnet": 2.0, "ftp": 1.5, "winbox": 2.0, "api": 1.5, "snmp": 1.0}
        for svc, pts in high_risk.items():
            if svc in info.get("services", []):
                score += pts
        score += len(info.get("vulnerabilities", [])) * 0.3
        return min(score, 10.0)
