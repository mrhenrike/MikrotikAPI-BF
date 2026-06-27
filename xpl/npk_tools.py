#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""NPK fetch and unpack helpers — port of mikrotik-tools getnpk.sh / reversenpk.sh."""

from __future__ import annotations

import re
import subprocess
import urllib.error
import urllib.request
from pathlib import Path
from typing import Dict, List, Optional

NPK_MIRRORS = [
    "https://download2.mikrotik.com/routeros/{ver}/{name}",
    "http://upgrade.mikrotik.com/routeros/{ver}/{name}",
    "http://admin.roset.cz/Mikrotik/routeros-ALL-{ver}/{name}",
    "http://mirror2.polsri.ac.id/MikroTik/RouterOS/RouterOS%20{ver}/{name}",
    "http://mirror.poliwangi.ac.id/mikrotik/{ver}/{name}",
    "http://www.hlucin.net/mikrotik/{ver}/{name}",
    "http://204.62.56.64/mikrotik/{ver}/{name}",
]


def npk_filename(version: str, arch: str = "x86") -> str:
    """Resolve NPK filename from version string (getnpk.sh logic)."""
    ver = version.strip()
    if re.search(r"^[a-z]+$", ver.split(".")[-1], re.I):
        ext = ver.split(".")[-1]
        ver = ".".join(ver.split(".")[:-1])
    else:
        ext = "npk"
    dashes = len(re.sub(r"[^-]", "", ver))
    if dashes == 0:
        name = f"routeros-{arch}-{ver}"
    elif dashes == 1:
        name = f"routeros-{ver}"
    else:
        name = ver
    name = name.lstrip("-")
    return f"{name}.{ext}"


def fetch_npk(version: str, dest_dir: str, arch: str = "x86", timeout: int = 60) -> Dict:
    """Download RouterOS NPK from official/alternate mirrors."""
    dest = Path(dest_dir)
    dest.mkdir(parents=True, exist_ok=True)
    fname = npk_filename(version, arch)
    out_path = dest / fname
    if out_path.is_file():
        return {"ok": True, "path": str(out_path), "cached": True}

    ver_tag = fname.rsplit("-", 1)[-1].replace(".npk", "").split("-")[-1]
    if "-" in fname:
        ver_tag = version

    errors: List[str] = []
    for tmpl in NPK_MIRRORS:
        url = tmpl.format(ver=ver_tag, name=fname)
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "MikrotikAPI-BF/3.15"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            if len(data) < 1024:
                errors.append(f"{url}: too small")
                continue
            out_path.write_bytes(data)
            return {"ok": True, "path": str(out_path), "url": url, "size": len(data)}
        except (urllib.error.URLError, OSError) as exc:
            errors.append(f"{url}: {exc}")

    return {"ok": False, "errors": errors}


def unpack_npk(npk_path: str, out_dir: Optional[str] = None) -> Dict:
    """Unpack NPK using unnpk if available, else internal parser extract."""
    npk = Path(npk_path)
    folder = Path(out_dir) if out_dir else npk.parent / npk.stem
    folder.mkdir(parents=True, exist_ok=True)

    if subprocess.run(["which", "unnpk"], capture_output=True).returncode == 0:
        r = subprocess.run(
            ["unnpk", "-xf", str(npk), "-C", str(folder)],
            capture_output=True, text=True,
        )
        if r.returncode == 0:
            squash = folder / "system.squashfs"
            if squash.is_file() and subprocess.run(["which", "unsquashfs"], capture_output=True).returncode == 0:
                subprocess.run(["unsquashfs", "-d", str(folder / "squashfs-root"), str(squash)], check=False)
            return {"ok": True, "method": "unnpk", "dir": str(folder)}

    from xpl.npk_decoder import NPKParser

    parser = NPKParser(str(npk))
    parts = parser.parts
    meta_path = folder / "parts.json"
    import json
    meta_path.write_text(
        json.dumps(
            [{"type": hex(p["type_id"]), "name": p.get("name"), "size": p["size"]} for p in parts],
            indent=2,
        ),
        encoding="utf-8",
    )
    for i, part in enumerate(parts):
        if part.get("data"):
            (folder / f"part_{i:02d}_{part['type_id']:04x}.bin").write_bytes(part["data"])
    return {"ok": True, "method": "internal_parser", "dir": str(folder), "parts": len(parts)}
