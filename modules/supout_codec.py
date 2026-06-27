#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""RouterOS supout.rif codec — tribit encode/decode + /proc archive (PR #16).

Port of mikrotik-tools decode_supout.py / encode_supout.py (Kirils Solovjovs)
with /proc archive support from darkk PR #16 (Leonid Evdokimov, 2024).

Reference: https://github.com/0ki/mikrotik-tools
"""

from __future__ import annotations

import base64
import errno
import io
import os
import re
import stat
import struct
import zlib
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

# tribitmap from encode_supout.py / decode_supout.py
_TRIBITMAP = [
    10, 11, 0, 1, 2, 3, 4, 5,
    14, 15, 16, 17, 6, 7, 8, 9,
    18, 19, 20, 21, 22, 23, 12, 13,
]
_REVT_TRIBITMAP = [
    2, 3, 4, 5, 6, 7, 12, 13, 14, 15, 0, 1, 22, 23, 8, 9,
    10, 11, 16, 17, 18, 19, 20, 21,
]

_SECTION_BEGIN = "--BEGIN ROUTEROS SUPOUT SECTION\r\n"
_SECTION_END = "--END ROUTEROS SUPOUT SECTION\r\n"
_LEGACY_MAGIC = b"\x8b\xbe\xa8\xbc"


def tribit_decode(content: bytes) -> bytes:
    """Decode tribit-encoded bytes (3 output bytes per 3 input bytes)."""
    out = bytearray()
    for i in range(0, len(content) - 1, 3):
        raw = content[i: i + 3]
        good = 0
        bad = raw[0] * 0x10000 + raw[1] * 0x100 + raw[2]
        for shift in _TRIBITMAP:
            good = (good << 1) + (1 if (bad & (0x800000 >> shift)) else 0)
        out.extend([(good >> 16) & 0xFF, (good >> 8) & 0xFF, good & 0xFF])
    return bytes(out)


def tribit_encode(content: bytes) -> bytes:
    """Encode bytes using reverse tribitmap (encode_supout.py)."""
    padded = content
    while len(padded) % 3:
        padded += b"\x00"
    out = bytearray()
    for i in range(0, len(padded) - 1, 3):
        good = 0
        bad = padded[i] * 0x10000 + padded[i + 1] * 0x100 + padded[i + 2]
        for mangle in _REVT_TRIBITMAP:
            good = (good << 1) + (1 if ((bad & (0x800000 >> mangle)) > 0) else 0)
        out.extend([(good >> 16) & 0xFF, (good >> 8) & 0xFF, good & 0xFF])
    return bytes(out)


def _split_sections_text(data: str) -> List[str]:
    norm = data.replace("\r\n", "\n")
    norm = norm.replace("--END ROUTEROS SUPOUT SECTION\n", "")
    return norm.split("--BEGIN ROUTEROS SUPOUT SECTION\n")


def _parse_section_blob(sect: str) -> Tuple[str, bytes]:
    cleaned = "".join(sect.strip().split()).replace("=", "A")
    if not cleaned:
        raise ValueError("empty section")
    raw = tribit_decode(base64.b64decode(cleaned))
    name, blob = raw.split(b"\x00", 1)
    return name.decode("ascii"), zlib.decompress(blob)


def encode_section(name: str, raw_content: bytes) -> str:
    """Encode one section into RouterOS supout text block."""
    payload = name.encode("ascii") + b"\x00" + zlib.compress(raw_content)
    tribit_data = tribit_encode(payload)
    reallen = len(base64.b64encode(payload).replace(b"=", b""))
    full_b64 = base64.b64encode(tribit_data).decode("ascii")
    b64 = full_b64[:reallen] + "=" * (len(full_b64) - reallen)
    lines = "\r\n".join(b64[i: i + 76] for i in range(0, len(b64), 76))
    return _SECTION_BEGIN + lines + "\r\n" + _SECTION_END


def build_supout_from_folder(folder: str) -> bytes:
    """Build supout.rif from a folder of section files (issue #14).

    Each file name becomes the section name; content is stored compressed.
    """
    parts: List[str] = []
    base = Path(folder)
    for path in sorted(base.iterdir()):
        if path.is_file() and not path.name.endswith(".rif"):
            parts.append(encode_section(path.name, path.read_bytes()))
    return "".join(parts).encode("utf-8")


class SupoutSection:
    __slots__ = ("index", "name", "compressed_size", "raw_size", "raw", "has_proc_archive")

    def __init__(
        self,
        index: int,
        name: str,
        compressed_size: int,
        raw: bytes,
    ) -> None:
        self.index = index
        self.name = name
        self.compressed_size = compressed_size
        self.raw = raw
        self.raw_size = len(raw)
        self.has_proc_archive = raw.startswith(b"\4\4\0\0\0\2") or raw.startswith(b"\4\0\0\0\4\0\0\0\2")


def parse_supout_rif(path: str) -> List[SupoutSection]:
    """Parse tribit-format supout.rif (mikrotik-tools format)."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    sections: List[SupoutSection] = []
    idx = 0
    for sect in _split_sections_text(text):
        try:
            name, raw = _parse_section_blob(sect)
        except (ValueError, zlib.error, base64.binascii.Error):
            continue
        idx += 1
        sections.append(SupoutSection(idx, name, len(sect), raw))
    return sections


def _itlv(fd: io.BytesIO, u32) -> Iterator[Tuple[int, bytes]]:
    while True:
        tag_b = fd.read(1)
        if not tag_b:
            break
        tag = int(tag_b[0])
        length = u32.unpack(fd.read(u32.size))[0]
        value = fd.read(length)
        yield tag, value


def extract_proc_archive(blob: bytes, dest: str, endian: str = "le") -> int:
    """Extract /proc-style ar archive from a supout section blob (PR #16)."""
    u32 = struct.Struct("<I") if endian == "le" else struct.Struct(">I")
    STAT, FNAME, DATA, MAGIC, END = 1, 2, 3, 4, 5
    prefix = os.path.realpath(dest)
    os.makedirs(prefix, exist_ok=True)
    tree: List[str] = []
    count = 0
    it = _itlv(io.BytesIO(blob), u32)
    t, v = next(it)
    if not (t == MAGIC and len(v) == u32.size and u32.unpack(v)[0] == 2):
        return 0

    for t, v in it:
        if t == END:
            if v:
                continue
            if tree:
                tree.pop()
            continue
        if t != FNAME:
            continue
        fname = v.decode("ascii", errors="replace")
        t2, v2 = next(it)
        if t2 == END and len(v2) == u32.size:
            continue
        if t2 != STAT:
            continue
        st_stat = u32.unpack(v2)[0]
        fmt = stat.S_IFMT(st_stat)
        if fmt == stat.S_IFDIR:
            tree.append(fname)
            sub = os.path.join(prefix, *tree)
            os.makedirs(sub, exist_ok=True)
        elif fmt in (stat.S_IFREG, stat.S_IFLNK):
            t3, v3 = next(it)
            fpath = os.path.join(prefix, *tree, fname)
            os.makedirs(os.path.dirname(fpath), exist_ok=True)
            with open(fpath, "wb") as out:
                while t3 == DATA:
                    if fmt == stat.S_IFLNK:
                        out.write(b"linkto: ")
                    out.write(v3)
                    t3, v3 = next(it)
            count += 1
    return count


def list_sections(path: str) -> List[Dict]:
    """Unified section listing — tribit text format or legacy binary magic."""
    p = Path(path)
    if not p.is_file():
        return []
    blob = p.read_bytes()
    head = blob[:4096]
    if _SECTION_BEGIN.encode() in head or b"BEGIN ROUTEROS SUPOUT" in head:
        return [
            {
                "name": s.name,
                "index": s.index,
                "size": s.raw_size,
                "compressed_hint": s.compressed_size,
                "proc_archive": s.has_proc_archive,
            }
            for s in parse_supout_rif(path)
        ]
    # legacy binary scanner (older captures)
    sections: List[Dict] = []
    data = blob
    pos = 0
    while pos < len(data) - 8:
        if data[pos: pos + 4] != _LEGACY_MAGIC:
            pos += 1
            continue
        pos += 4
        name_end = data.find(b"\x00", pos)
        if name_end < 0:
            break
        name = data[pos:name_end].decode("utf-8", errors="replace")
        pos = name_end + 1
        if pos + 4 > len(data):
            break
        size = struct.unpack(">I", data[pos: pos + 4])[0]
        pos += 4
        sections.append({"name": name, "offset": pos, "size": size, "proc_archive": False})
        pos += size
    return sections


def dump_section(path: str, section_name: str) -> Optional[str]:
    """Return decompressed section text by name."""
    for s in parse_supout_rif(path):
        if s.name == section_name or s.name.rstrip("/") == section_name.rstrip("/"):
            try:
                return s.raw.decode("utf-8")
            except UnicodeDecodeError:
                return s.raw.decode("latin-1", errors="replace")
    # legacy fallback
    data = Path(path).read_bytes()
    for sec in list_sections(path):
        if sec.get("name") == section_name and "offset" in sec:
            raw = data[sec["offset"]: sec["offset"] + sec["size"]]
            try:
                return raw.decode("utf-8")
            except UnicodeDecodeError:
                return raw.decode("latin-1", errors="replace")
    return None
