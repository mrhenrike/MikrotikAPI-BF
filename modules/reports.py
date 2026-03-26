#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Pentest Report Generator — MikrotikAPI-BF
==========================================
Generates professional pentest reports in text and HTML formats,
combining fingerprint results, discovered credentials, and exploit findings.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional


class PentestReportGenerator:
    """
    Generate structured pentest reports.

    Args:
        target:          Target IP / hostname.
        fingerprint:     Dict from MikrotikFingerprinter.fingerprint_device().
        credentials:     List of dicts with keys ``user``, ``pass``, ``services``.
        exploit_results: List of exploit finding dicts (from xpl module).
        output_dir:      Directory for report files.
    """

    def __init__(
        self,
        target: str,
        fingerprint: Optional[Dict] = None,
        credentials: Optional[List[Dict]] = None,
        exploit_results: Optional[List[Dict]] = None,
        output_dir: str = "results",
    ) -> None:
        self.target = target
        self.fingerprint = fingerprint or {}
        self.credentials = credentials or []
        self.exploit_results = exploit_results or []
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._generated_at = datetime.now().isoformat()

    # ------------------------------------------------------------------
    # Text report
    # ------------------------------------------------------------------

    def generate_text(self) -> Path:
        """Generate a plaintext pentest report."""
        path = self.output_dir / f"report_{self.target.replace('.', '_')}_{self.timestamp}.txt"
        lines = [
            "=" * 70,
            "MIKROTIK PENTEST REPORT",
            "=" * 70,
            f"Target       : {self.target}",
            f"Generated at : {self._generated_at}",
            f"Tool         : MikrotikAPI-BF",
            "",
        ]

        # Fingerprint section
        if self.fingerprint:
            lines += [
                "── FINGERPRINT ──────────────────────────────────────────",
                f"  Is Mikrotik    : {'YES' if self.fingerprint.get('is_mikrotik') else 'NO'}",
                f"  RouterOS Ver   : {self.fingerprint.get('routeros_version', 'Unknown')}",
                f"  Model          : {self.fingerprint.get('model', 'Unknown')}",
                f"  Open Ports     : {', '.join(map(str, self.fingerprint.get('open_ports', [])))}",
                f"  Services       : {', '.join(self.fingerprint.get('services', []))}",
                f"  Risk Score     : {self.fingerprint.get('risk_score', 0):.1f}/10",
                "",
            ]
            if self.fingerprint.get("vulnerabilities"):
                lines.append("  Vulnerabilities:")
                for v in self.fingerprint["vulnerabilities"]:
                    lines.append(f"    - {v}")
                lines.append("")

        # Credentials section
        lines.append("── CREDENTIALS FOUND ────────────────────────────────────")
        if self.credentials:
            for i, c in enumerate(self.credentials, 1):
                lines.append(
                    f"  [{i:02}] {c.get('user', '?')}:{c.get('pass', '?')} "
                    f"({', '.join(c.get('services', []))})"
                )
        else:
            lines.append("  None.")
        lines.append("")

        # Exploits section
        if self.exploit_results:
            lines.append("── EXPLOIT FINDINGS ─────────────────────────────────────")
            for ex in self.exploit_results:
                lines += [
                    f"  CVE            : {ex.get('cve_id', 'N/A')}",
                    f"  Severity       : {ex.get('severity', 'N/A')}",
                    f"  Description    : {ex.get('description', 'N/A')}",
                    f"  Status         : {ex.get('status', 'N/A')}",
                    "",
                ]

        lines += ["=" * 70, "END OF REPORT", "=" * 70]

        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # HTML report
    # ------------------------------------------------------------------

    def generate_html(self) -> Path:
        """Generate an HTML pentest report."""
        path = self.output_dir / f"report_{self.target.replace('.', '_')}_{self.timestamp}.html"

        creds_rows = ""
        for c in self.credentials:
            creds_rows += (
                f"<tr><td>{c.get('user','')}</td>"
                f"<td>{c.get('pass','')}</td>"
                f"<td>{', '.join(c.get('services',[]))}</td></tr>"
            )
        creds_table = (
            f"<table><tr><th>Username</th><th>Password</th><th>Services</th></tr>"
            f"{creds_rows}</table>"
            if self.credentials
            else "<p>None.</p>"
        )

        vuln_items = "".join(
            f"<li>{v}</li>" for v in self.fingerprint.get("vulnerabilities", [])
        )

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>MikrotikAPI-BF Pentest Report — {self.target}</title>
  <style>
    body {{ font-family: 'Courier New', monospace; background:#0d1117; color:#c9d1d9; margin:2em; }}
    h1 {{ color:#58a6ff; }} h2 {{ color:#388bfd; border-bottom:1px solid #30363d; padding-bottom:4px; }}
    table {{ border-collapse:collapse; width:100%; }} th,td {{ border:1px solid #30363d; padding:6px 10px; }}
    th {{ background:#161b22; color:#58a6ff; }} tr:nth-child(even) {{ background:#161b22; }}
    .badge-high {{ color:#f85149; }} .badge-med {{ color:#e3b341; }} .badge-low {{ color:#3fb950; }}
    .meta {{ color:#8b949e; font-size:0.85em; }} .box {{ background:#161b22; border:1px solid #30363d;
    border-radius:6px; padding:1em; margin-bottom:1em; }}
  </style>
</head>
<body>
  <h1>MikrotikAPI-BF — Pentest Report</h1>
  <div class="box meta">
    <strong>Target:</strong> {self.target} &nbsp;|&nbsp;
    <strong>Generated:</strong> {self._generated_at} &nbsp;|&nbsp;
    <strong>Tool:</strong> MikrotikAPI-BF
  </div>

  <h2>Fingerprint</h2>
  <div class="box">
    <p><strong>Is Mikrotik:</strong> {'YES' if self.fingerprint.get('is_mikrotik') else 'NO'}</p>
    <p><strong>RouterOS Version:</strong> {self.fingerprint.get('routeros_version', 'Unknown')}</p>
    <p><strong>Model:</strong> {self.fingerprint.get('model', 'Unknown')}</p>
    <p><strong>Open Ports:</strong> {', '.join(map(str, self.fingerprint.get('open_ports', [])))}</p>
    <p><strong>Services:</strong> {', '.join(self.fingerprint.get('services', []))}</p>
    <p><strong>Risk Score:</strong> {self.fingerprint.get('risk_score', 0):.1f}/10</p>
    {'<ul>' + vuln_items + '</ul>' if vuln_items else ''}
  </div>

  <h2>Credentials Found</h2>
  <div class="box">{creds_table}</div>

  <h2>Exploit Findings</h2>
  <div class="box">
    {'<p>No applicable exploits found.</p>' if not self.exploit_results else
     '<br>'.join(
         f"<strong>{e.get('cve_id','N/A')}</strong> — {e.get('description','')}"
         for e in self.exploit_results
     )}
  </div>
</body>
</html>"""

        path.write_text(html, encoding="utf-8")
        return path

    # ------------------------------------------------------------------
    # JSON report (machine-readable)
    # ------------------------------------------------------------------

    def generate_json(self) -> Path:
        """Generate a machine-readable JSON report."""
        path = self.output_dir / f"report_{self.target.replace('.', '_')}_{self.timestamp}.json"
        data = {
            "meta": {
                "target": self.target,
                "generated_at": self._generated_at,
                "tool": "MikrotikAPI-BF",
            },
            "fingerprint": self.fingerprint,
            "credentials": self.credentials,
            "exploits": self.exploit_results,
        }
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        return path

    def generate_all(self) -> Dict[str, Path]:
        """Generate all report formats and return a format→path dict."""
        return {
            "txt": self.generate_text(),
            "html": self.generate_html(),
            "json": self.generate_json(),
        }
