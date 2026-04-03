#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: see version.py (canonical source)

"""
NPK Package Decoder & Analyzer — MikrotikAPI-BF
================================================
Parses RouterOS NPK package files and extracts part metadata, embedded
scripts, signatures, and file system containers.

NPK part types (from 0ki/mikrotik-tools research by Kirils Solovjovs):

  ID       | Name
  ---------|-------------------------------
  0x0100   | Part info (mandatory)
  0x0200   | Part description (mandatory)
  0x0300   | Dependencies (mandatory)
  0x0400   | File container
  0x0500   | Install script (libinstall, up to RouterOS 2.7.xx)
  0x0700   | Install script (bash)
  0x0800   | Uninstall script (bash)
  0x0900   | Signature (mandatory, since 3.22)
  0x1000   | Architecture (mandatory, since 2.9)
  0x1100   | Package conflicts (3.14-3.22)
  0x1200   | Package info (since 2.9)
  0x1300   | Part features (since 2.9)
  0x1400   | Package features (since 2.9)
  0x1500   | SquashFS block (package-only, since 6.0beta3)
  0x1600   | Zero padding
  0x1700   | Digest (package-only, since 6.30)
  0x1800   | Channel (package-only, since 6.33)

Security relevance
------------------
CVE-2019-3977 / CVE-2019-3976: An attacker with FTP/API write access can
stage a crafted NPK file. During installation, RouterOS processes it with
elevated privileges — enabling arbitrary code execution or file read.

References
----------
- https://github.com/0ki/mikrotik-tools (Kirils Solovjovs)
- https://nvd.nist.gov/vuln/detail/CVE-2019-3977
- https://nvd.nist.gov/vuln/detail/CVE-2019-3976
"""

import hashlib
import logging
import struct
from pathlib import Path
from typing import Dict, List, Optional, Tuple

log = logging.getLogger(__name__)


# ── NPK Part type registry ────────────────────────────────────────────────────

NPK_PARTS: Dict[int, Dict] = {
    0x0100: {"name": "Part info",                  "mandatory": True,  "since": "forever"},
    0x0200: {"name": "Part description",           "mandatory": True,  "since": "forever"},
    0x0300: {"name": "Dependencies",               "mandatory": True,  "since": "forever"},
    0x0400: {"name": "File container",             "mandatory": False, "since": "forever"},
    0x0500: {"name": "Install script (libinstall)","mandatory": False, "since": "forever", "until": "2.7.xx"},
    0x0600: {"name": "Uninstall script (libinstall)","mandatory": False,"since": "never"},
    0x0700: {"name": "Install script (bash)",      "mandatory": False, "since": "forever"},
    0x0800: {"name": "Uninstall script (bash)",    "mandatory": False, "since": "forever"},
    0x0900: {"name": "Signature",                  "mandatory": True,  "since": "3.22"},
    0x1000: {"name": "Architecture",               "mandatory": True,  "since": "2.9"},
    0x1100: {"name": "Package conflicts",          "mandatory": False, "since": "3.14", "until": "3.22"},
    0x1200: {"name": "Package info",               "mandatory": False, "since": "2.9"},
    0x1300: {"name": "Part features",              "mandatory": False, "since": "2.9"},
    0x1400: {"name": "Package features",           "mandatory": False, "since": "2.9"},
    0x1500: {"name": "SquashFS block",             "mandatory": False, "since": "6.0beta3", "package_only": True},
    0x1600: {"name": "Zero padding",               "mandatory": False, "since": "6.0beta3"},
    0x1700: {"name": "Digest",                     "mandatory": False, "since": "6.30",    "package_only": True},
    0x1800: {"name": "Channel",                    "mandatory": False, "since": "6.33",    "package_only": True},
}

# NPK magic header
NPK_MAGIC = bytes([0xC3, 0xAD, 0x11, 0x94, 0x3B, 0x71, 0xF3, 0x86])


# ── NPK file parser ───────────────────────────────────────────────────────────

class NPKParser:
    """Parse RouterOS NPK package files.

    Args:
        npk_path: Path to the .npk file.

    Raises:
        ValueError: If the file is not a valid NPK.
    """

    def __init__(self, npk_path: str) -> None:
        self.path = npk_path
        self.parts: List[Dict] = []
        self._data: bytes = b""
        self._parse()

    def _parse(self) -> None:
        """Parse the NPK binary format and populate self.parts."""
        with open(self.path, "rb") as f:
            self._data = f.read()

        if len(self._data) < 16:
            raise ValueError(f"File too small to be a valid NPK: {self.path}")

        # Verify magic (first 8 bytes or match type ID pattern)
        # NPK files use a simple TLV structure: type(2) + length(4) + data
        pos = 0
        while pos + 6 < len(self._data):
            try:
                part_type = struct.unpack(">H", self._data[pos: pos + 2])[0]
                part_len  = struct.unpack(">I", self._data[pos + 2: pos + 6])[0]
            except struct.error:
                break

            if part_type not in NPK_PARTS:
                # Try to skip — might be alignment padding
                if part_type == 0:
                    pos += 1
                    continue
                log.debug("Unknown NPK part type 0x%04X at offset %d — stopping", part_type, pos)
                break

            part_data = self._data[pos + 6: pos + 6 + part_len]
            meta = dict(NPK_PARTS.get(part_type, {"name": f"Unknown (0x{part_type:04X})"}))
            meta.update({
                "type_id": part_type,
                "offset":  pos,
                "size":    part_len,
                "data":    part_data,
            })
            self.parts.append(meta)
            pos += 6 + part_len

        log.info("[npk] Parsed %d part(s) from %s", len(self.parts), self.path)

    def get_part(self, part_type: int) -> Optional[Dict]:
        """Return the first part matching a type ID, or None."""
        for p in self.parts:
            if p["type_id"] == part_type:
                return p
        return None

    def get_part_info(self) -> Optional[str]:
        """Return the package name/version from Part info (0x0100)."""
        part = self.get_part(0x0100)
        if not part:
            return None
        try:
            return part["data"].decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            return None

    def get_architecture(self) -> Optional[str]:
        """Return the target architecture from the Architecture part (0x1000)."""
        part = self.get_part(0x1000)
        if not part:
            return None
        try:
            return part["data"].decode("utf-8", errors="replace").rstrip("\x00")
        except Exception:
            return None

    def get_install_script(self) -> Optional[str]:
        """Return the bash install script content (0x0700) if present."""
        part = self.get_part(0x0700)
        if not part:
            return None
        try:
            return part["data"].decode("utf-8", errors="replace")
        except Exception:
            return None

    def get_signature(self) -> Optional[bytes]:
        """Return the package signature bytes (0x0900)."""
        part = self.get_part(0x0900)
        return part["data"] if part else None

    def verify_digest(self) -> Optional[bool]:
        """Verify the package digest (0x1700) against SHA256 of data before digest part.

        Returns:
            True if digest matches, False if mismatch, None if no digest part found.
        """
        digest_part = self.get_part(0x1700)
        if not digest_part:
            return None

        # Data before the digest part
        data_before = self._data[: digest_part["offset"]]
        computed = hashlib.sha256(data_before).digest()
        stored   = digest_part["data"]

        match = computed == stored
        if not match:
            log.warning("[npk] Digest mismatch! Stored=%s Computed=%s",
                        stored.hex(), computed.hex())
        return match

    def print_summary(self) -> None:
        """Print a formatted summary of all NPK parts."""
        info = self.get_part_info()
        arch = self.get_architecture()
        print(f"\n  [NPK] File: {self.path}")
        print(f"  Package: {info or 'unknown'}  Architecture: {arch or 'unknown'}")
        print(f"  Parts ({len(self.parts)}):")
        print(f"  {'ID':8}  {'Name':35}  {'Size':10}  {'Offset'}")
        print("  " + "-" * 75)
        for p in self.parts:
            print(f"  0x{p['type_id']:04X}    {p['name'][:35]:35}  {p['size']:10,}  {p['offset']}")
        digest_ok = self.verify_digest()
        if digest_ok is not None:
            status = "VALID" if digest_ok else "INVALID (possible tampering)"
            print(f"\n  Digest: {status}")
        print()


# ── Security analysis ─────────────────────────────────────────────────────────

class NPKSecurityAnalyzer:
    """Analyze NPK files for security-relevant indicators.

    Used for:
    - CVE-2019-3977/3976 PoC: determine if an NPK can stage arbitrary code
    - Detecting unsigned/tampered packages
    - Identifying install scripts that could be leveraged
    """

    @classmethod
    def analyze(cls, npk_path: str) -> Dict:
        """Analyze an NPK file for security properties.

        Args:
            npk_path: Path to .npk file.

        Returns:
            Dict with keys: valid_digest, has_signature, has_install_script,
            install_script, architecture, package_name, suspicious_indicators.
        """
        result: Dict = {
            "path":                  npk_path,
            "package_name":          None,
            "architecture":          None,
            "valid_digest":          None,
            "has_signature":         False,
            "has_install_script":    False,
            "install_script":        None,
            "suspicious_indicators": [],
        }

        try:
            parser = NPKParser(npk_path)
        except (ValueError, OSError) as exc:
            result["error"] = str(exc)
            return result

        result["package_name"]       = parser.get_part_info()
        result["architecture"]       = parser.get_architecture()
        result["valid_digest"]       = parser.verify_digest()
        result["has_signature"]      = bool(parser.get_signature())

        script = parser.get_install_script()
        if script:
            result["has_install_script"] = True
            result["install_script"]     = script

            # Flag suspicious patterns
            dangerous = ["wget", "curl", "nc ", "netcat", "bash -i", "/dev/tcp",
                         "chmod +x", "eval ", "exec ", "base64"]
            for pat in dangerous:
                if pat.lower() in script.lower():
                    result["suspicious_indicators"].append(
                        f"Dangerous pattern in install script: '{pat}'"
                    )

        if result["valid_digest"] is False:
            result["suspicious_indicators"].append(
                "Digest mismatch — package may have been tampered with (CVE-2019-3977 vector)"
            )

        if not result["has_signature"]:
            result["suspicious_indicators"].append(
                "No Signature part — package predates 3.22 or was crafted without signing"
            )

        return result

    @classmethod
    def check_cve_2019_3977(cls, npk_path: str) -> Dict:
        """Check if an NPK is crafted in a way exploitable via CVE-2019-3977.

        CVE-2019-3977: An attacker with FTP/API write access can upload a
        crafted NPK to flash/. Upon boot or manual install, RouterOS processes
        the NPK, executing the embedded install script with elevated privileges.

        Args:
            npk_path: Path to .npk file (could be legitimate or crafted).

        Returns:
            Dict with vulnerable (bool) and evidence (str) keys.
        """
        analysis = cls.analyze(npk_path)

        if "error" in analysis:
            return {"vulnerable": False, "evidence": f"Parse error: {analysis['error']}"}

        indicators = analysis["suspicious_indicators"]
        has_script = analysis["has_install_script"]

        vulnerable = bool(indicators or (has_script and not analysis["has_signature"]))
        evidence = (
            f"Package: {analysis['package_name']} | Arch: {analysis['architecture']} | "
            f"Has install script: {has_script} | Signature: {analysis['has_signature']} | "
            f"Digest OK: {analysis['valid_digest']} | "
            f"Indicators: {indicators if indicators else 'none'}"
        )

        return {"vulnerable": vulnerable, "evidence": evidence, "details": analysis}


def analyze_npk_artifact(npk_path: str) -> Dict[str, object]:
    """Classify NPK package for hardening utility and attack-surface impact.

    Args:
        npk_path: Path to a `.npk` package.

    Returns:
        Dict with package purpose and security classification.
    """
    analysis = NPKSecurityAnalyzer.analyze(npk_path)
    package_name = (analysis.get("package_name") or "").lower()

    notes: List[str] = []
    impact = "medium"
    hardening_useful = True

    if "container" in package_name:
        impact = "high"
        notes.append("Container runtime package increases attack surface; install only if required.")
    elif "tr069" in package_name:
        impact = "high"
        notes.append("TR-069 client may expose management workflow risks if misconfigured.")
    elif "user-manager" in package_name:
        impact = "high"
        notes.append("AAA package adds web/auth interfaces that require strict hardening.")
    elif "wireless" in package_name or "wifi" in package_name:
        impact = "medium"
        notes.append("Wireless stack not required for pure CHR unless explicit use case exists.")
    elif "security" in package_name:
        impact = "low"
        notes.append("Security package can be useful for defensive controls.")
    else:
        notes.append("Validate package necessity against minimum-feature principle.")

    if analysis.get("valid_digest") is False:
        impact = "high"
        notes.append("Digest mismatch indicates potential tampering.")

    if analysis.get("has_signature") is False:
        notes.append("Missing signature part; verify source and integrity before deployment.")

    return {
        "path": npk_path,
        "package_name": analysis.get("package_name"),
        "architecture": analysis.get("architecture"),
        "hardening_useful": hardening_useful,
        "attack_surface_impact": impact,
        "notes": notes,
    }

