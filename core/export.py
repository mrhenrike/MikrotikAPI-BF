#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Result Export Module — MikrotikAPI-BF
=======================================
Exports brute-force results to JSON, CSV, XML, and TXT formats.
"""

import csv
import json
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from typing import Dict, List


class ResultExporter:
    """
    Export attack results to multiple formats.

    Args:
        results:    List of credential dicts with keys ``user``, ``pass``, ``services``.
        target:     Target IP / hostname used for filenames.
        output_dir: Directory to save exported files (created if absent).
    """

    def __init__(self, results: List[Dict], target: str, output_dir: str = "results") -> None:
        self.results = results
        self.target = target
        self.output_dir = Path(output_dir)
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _fname(self, ext: str) -> Path:
        safe = self.target.replace(".", "_").replace(":", "_")
        return self.output_dir / f"mikrotik_{safe}_{self.timestamp}.{ext}"

    def _meta(self) -> Dict:
        return {
            "target": self.target,
            "timestamp": datetime.now().isoformat(),
            "tool": "MikrotikAPI-BF",
            "total_found": len(self.results),
        }

    # ------------------------------------------------------------------
    # Export methods
    # ------------------------------------------------------------------

    def export_json(self) -> Path:
        """Export results as a structured JSON file."""
        path = self._fname("json")
        data = {"scan_info": self._meta(), "credentials": self.results}
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(data, fh, indent=4, ensure_ascii=False)
        return path

    def export_csv(self) -> Path:
        """Export results as a CSV file compatible with Excel/LibreOffice."""
        path = self._fname("csv")
        with open(path, "w", newline="", encoding="utf-8") as fh:
            writer = csv.DictWriter(fh, fieldnames=["username", "password", "services", "target"])
            writer.writeheader()
            for r in self.results:
                writer.writerow(
                    {
                        "username": r.get("user", ""),
                        "password": r.get("pass", ""),
                        "services": ", ".join(r.get("services", [])),
                        "target": r.get("target", self.target),
                    }
                )
        return path

    def export_xml(self) -> Path:
        """Export results as a pretty-printed XML file."""
        path = self._fname("xml")
        root = ET.Element("mikrotik_scan")
        info_el = ET.SubElement(root, "scan_info")
        for k, v in self._meta().items():
            ET.SubElement(info_el, k).text = str(v)

        creds_el = ET.SubElement(root, "credentials")
        for r in self.results:
            cred_el = ET.SubElement(creds_el, "credential")
            ET.SubElement(cred_el, "username").text = r.get("user", "")
            ET.SubElement(cred_el, "password").text = r.get("pass", "")
            ET.SubElement(cred_el, "target").text = r.get("target", self.target)
            svcs_el = ET.SubElement(cred_el, "services")
            for svc in r.get("services", []):
                ET.SubElement(svcs_el, "service").text = svc

        self._indent_xml(root)
        ET.ElementTree(root).write(path, encoding="utf-8", xml_declaration=True)
        return path

    def export_txt(self) -> Path:
        """Export results as a simple ``user:pass`` text file."""
        path = self._fname("txt")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write("# MikrotikAPI-BF – Credential Results\n")
            for k, v in self._meta().items():
                fh.write(f"# {k}: {v}\n")
            fh.write("\n")
            for r in self.results:
                services = ", ".join(r.get("services", []))
                fh.write(f"{r.get('user', '')}:{r.get('pass', '')} ({services})\n")
        return path

    def export_all(self) -> Dict[str, Path]:
        """Export to all formats and return a dict of format→path."""
        return {
            "json": self.export_json(),
            "csv": self.export_csv(),
            "xml": self.export_xml(),
            "txt": self.export_txt(),
        }

    # ------------------------------------------------------------------
    # XML formatting helper
    # ------------------------------------------------------------------

    @staticmethod
    def _indent_xml(elem: ET.Element, level: int = 0) -> None:
        pad = "\n" + "  " * level
        if len(elem):
            if not elem.text or not elem.text.strip():
                elem.text = pad + "  "
            for child in elem:
                ResultExporter._indent_xml(child, level + 1)
            if not child.tail or not child.tail.strip():  # type: ignore[possibly-undefined]
                child.tail = pad  # type: ignore[possibly-undefined]
        if level and (not elem.tail or not elem.tail.strip()):
            elem.tail = pad
