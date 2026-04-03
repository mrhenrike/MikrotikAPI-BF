#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: 1.0.0

"""
Offline Artifact Analyzer — MikrotikAPI-BF
==========================================
Analyzes downloaded MikroTik artifacts (NPK, MIB, Winbox, Netinstall, Flashfig)
to classify security relevance, hardening utility, and potential attack surface.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Dict, List

from xpl.npk_decoder import NPKSecurityAnalyzer, analyze_npk_artifact


class OfflineArtifactAnalyzer:
    """Analyze MikroTik artifact directories."""

    NPK_EXTENSIONS = {".npk"}
    MIB_EXTENSIONS = {".mib"}
    EXECUTABLE_EXTENSIONS = {".exe"}
    ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz"}
    IMAGE_EXTENSIONS = {".ova", ".img", ".vdi", ".iso"}

    def analyze_directory(self, root_path: str) -> Dict[str, object]:
        """Walk directory and return per-artifact classification."""
        root = Path(root_path)
        findings: List[Dict[str, object]] = []
        for file_path in sorted(path for path in root.rglob("*") if path.is_file()):
            findings.append(self.analyze_file(file_path))
        return {
            "root": str(root),
            "total_files": len(findings),
            "findings": findings,
        }

    def analyze_file(self, file_path: Path) -> Dict[str, object]:
        """Analyze a single artifact and classify risk/usage."""
        suffix = file_path.suffix.lower()
        size = file_path.stat().st_size
        digest = self._sha256(file_path)
        base_result: Dict[str, object] = {
            "path": str(file_path),
            "name": file_path.name,
            "size": size,
            "sha256": digest,
            "category": "other",
            "hardening_useful": False,
            "attack_surface_impact": "low",
            "notes": [],
        }

        if suffix in self.NPK_EXTENSIONS:
            npk_info = NPKSecurityAnalyzer.analyze(str(file_path))
            matrix = analyze_npk_artifact(str(file_path))
            base_result.update(
                {
                    "category": "npk",
                    "hardening_useful": True,
                    "attack_surface_impact": matrix.get("attack_surface_impact", "medium"),
                    "notes": matrix.get("notes", []),
                    "npk_analysis": npk_info,
                }
            )
            return base_result

        if suffix in self.MIB_EXTENSIONS:
            base_result.update(
                {
                    "category": "mib",
                    "hardening_useful": True,
                    "attack_surface_impact": "medium",
                    "notes": [
                        "Useful for SNMP auditing and OID mapping.",
                        "Can improve attacker enumeration quality if SNMP exposed.",
                    ],
                }
            )
            return base_result

        if suffix in self.EXECUTABLE_EXTENSIONS:
            lower_name = file_path.name.lower()
            notes: List[str] = []
            impact = "medium"
            useful = False
            if "winbox" in lower_name:
                useful = True
                notes.append("Administrative client for RouterOS operations.")
            if "netinstall" in lower_name:
                useful = True
                impact = "high"
                notes.append("Provisioning/recovery utility; must be controlled in trusted environment.")
            if "flashfig" in lower_name:
                useful = True
                impact = "high"
                notes.append("Mass provisioning utility; misconfigurations propagate at scale.")
            base_result.update(
                {
                    "category": "binary-tool",
                    "hardening_useful": useful,
                    "attack_surface_impact": impact,
                    "notes": notes or ["Binary tool should be integrity-checked before use."],
                }
            )
            return base_result

        if suffix in self.ARCHIVE_EXTENSIONS:
            base_result.update(
                {
                    "category": "archive",
                    "hardening_useful": True,
                    "attack_surface_impact": "medium",
                    "notes": ["Archive package; verify integrity and source authenticity."],
                }
            )
            return base_result

        if suffix in self.IMAGE_EXTENSIONS:
            base_result.update(
                {
                    "category": "image",
                    "hardening_useful": True,
                    "attack_surface_impact": "low",
                    "notes": ["Base image for deployment; verify checksums before import."],
                }
            )
            return base_result

        return base_result

    @staticmethod
    def _sha256(file_path: Path) -> str:
        digest = hashlib.sha256()
        with file_path.open("rb") as handle:
            for block in iter(lambda: handle.read(65536), b""):
                digest.update(block)
        return digest.hexdigest()
