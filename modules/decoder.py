#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)
# Version: see version.py (canonical source)

"""
RouterOS Credential & File Decoder — MikrotikAPI-BF
=====================================================
Decodes RouterOS proprietary binary file formats to extract credentials,
configurations and diagnostic data obtained through exploitation.

Supported formats
-----------------
- **user.dat / user.idx** — user credential database (recovered via CVE-2018-14847)
- **group.dat / group.idx** — user group database
- **.backup** — RouterOS configuration backup archive
- **supout.rif** — support output (diagnostic) file sections

Password decryption algorithm (Kirils Solovjovs, 2017):
    key = MD5(username + "283i4jfkai3389")   # 16-byte digest
    plaintext = XOR(encrypted_password, key * 16)

References
----------
- https://github.com/0ki/mikrotik-tools (original Python 2 by Kirils Solovjovs)
- http://kirils.org/slides/2017-09-15_prez_15_MT_Balccon_pub.pdf
- https://nvd.nist.gov/vuln/detail/CVE-2018-14847 (credential file extraction)
"""

import hashlib
import logging
import os
import re
import socket
import struct
import warnings
from collections import OrderedDict
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

log = logging.getLogger(__name__)


# ── MT DAT/IDX binary format decoder (Python 3 port of mt_dat_decoder.py) ────

class MTDatDecoder:
    """Parse RouterOS proprietary .dat / .idx binary database files.

    This is a Python 3 port of Kirils Solovjovs' mt_dat_decoder.py
    (https://github.com/0ki/mikrotik-tools), updated for Python 3 semantics
    (bytes vs str, hashlib instead of md5, int instead of long).

    Args:
        dat_path: Path to the .dat file.
        idx_path: Optional path to the .idx index file. If None, parses .dat
                  sequentially without index.
    """

    _BLOCK_NAMES: Dict[int, str] = {
        0xFE0009: "comment",
        0xFE0001: "record_id",
        0xFE000A: "disabled",
        0xFE000D: "default",
        0xFFFFFF: "index_id",
        0xFE0008: "active",
        0xFE0010: "name",
    }

    def __init__(self, dat_path: str, idx_path: Optional[str] = None) -> None:
        self._dat = open(dat_path, "rb")
        self._idx = open(idx_path, "rb") if idx_path else None
        self._ip = 0
        self.mapping: Dict = dict(self._BLOCK_NAMES)
        self.parsers: Dict = {}
        self.filters: Dict = {}
        self.decode = False
        self.preserve_order = False

    def __iter__(self) -> Iterator:
        return self

    def __next__(self) -> Optional[Dict]:
        if self._idx is None:
            # Sequential mode (no index)
            try:
                raw = self._dat.read(2)
                if len(raw) < 2:
                    raise StopIteration
                size = struct.unpack("<H", raw)[0]
                record_data = self._dat.read(size - 2)
                return self._parse_record(record_data)
            except struct.error:
                raise StopIteration

        # Index mode
        iid = 0xFFFFFFFF
        while iid == 0xFFFFFFFF:
            entry = self._idx.read(12)
            if len(entry) < 12:
                raise StopIteration
            iid = struct.unpack("<I", entry[0:4])[0]
            ilen = struct.unpack("<I", entry[4:8])[0]
            isep = struct.unpack("<I", entry[8:12])[0]
            self._ip += ilen

        if isep != 5:
            warnings.warn(f"Non-standard index separator 0x{isep:08X}")

        self._dat.seek(self._ip - ilen)
        raw = self._dat.read(2)
        if len(raw) < 2:
            raise StopIteration
        size = struct.unpack("<H", raw)[0]
        record_data = self._dat.read(size - 2)
        parsed = self._parse_record(record_data)
        if parsed is None:
            return None

        iid_key = "index_id" if self.decode else f"_${0xFFFFFF:x}"
        parsed[iid_key] = iid
        return parsed

    def _parse_value(self, block_id_raw: int, block_id: str, block_type: int, data):
        """Apply custom parsers/filters to a parsed value."""
        if block_id in self.parsers:
            result = self.parsers[block_id](data)
            if result is not None:
                return result
        if block_id_raw in self.parsers:
            result = self.parsers[block_id_raw](data)
            if result is not None:
                return result
        if block_type in self.filters:
            result = self.filters[block_type](data)
            if result is not None:
                return result
        return data

    def _parse_record(self, record: bytes, top_id: int = 0) -> Optional[Dict]:
        """Parse a single binary MT DAT record."""
        if len(record) < 2 or record[0:2] != b"M2":
            warnings.warn("Not a valid MT DAT record (missing M2 header)")
            return None

        alldata = OrderedDict() if self.preserve_order else {}
        pos = 2

        while pos + 4 < len(record):
            bmarker = struct.unpack("<I", record[pos: pos + 4])[0]
            pos += 4
            bid_raw = bmarker & 0xFFFFFF
            btype = bmarker >> 24
            blen = 0
            data = None
            mtype = " "

            try:
                if btype == 0x21:       # short string
                    blen = record[pos]
                    pos += 1
                    data = record[pos: pos + blen].decode("utf-8", errors="replace")
                    mtype = "s"
                elif btype == 0x31:     # MAC address (bytes list)
                    blen = record[pos]
                    pos += 1
                    data = list(record[pos: pos + blen])
                    mtype = "r"
                elif btype == 0x08:     # uint32
                    blen = 4
                    data = struct.unpack("<I", record[pos: pos + blen])[0]
                    mtype = "u"
                elif btype == 0x10:     # uint64
                    blen = 8
                    data = struct.unpack("<Q", record[pos: pos + blen])[0]
                    mtype = "q"
                elif btype == 0x18:     # 128-bit integer (IPv6)
                    blen = 16
                    data = list(record[pos: pos + blen])
                    mtype = "a"
                elif btype == 0x09:     # byte
                    blen = 1
                    data = record[pos]
                    mtype = "u"
                elif btype == 0x29:     # single M2 sub-block
                    sub_size = record[pos]
                    blen = 1
                    data = self._parse_record(record[pos + 1: pos + 1 + sub_size],
                                              top_id=(top_id << 24) + bid_raw)
                    pos += sub_size
                    mtype = "M"
                elif btype == 0xA8:     # array of M2 sub-blocks
                    blen = 2
                    array_size = struct.unpack("<H", record[pos: pos + blen])[0]
                    parser = 0
                    data = []
                    pos_inner = pos + blen
                    while parser < array_size:
                        parser += 1
                        sub_size = struct.unpack("<H", record[pos_inner: pos_inner + 2])[0]
                        pos_inner += 2
                        data.append(self._parse_record(record[pos_inner: pos_inner + sub_size],
                                                       top_id=(top_id << 24) + bid_raw))
                        pos_inner += sub_size - 2
                    pos = pos_inner - blen
                    mtype = "M"
                elif btype == 0x88:     # array of uint32
                    blen = 2
                    array_size = struct.unpack("<H", record[pos: pos + blen])[0]
                    data = []
                    for _ in range(array_size):
                        data.append(struct.unpack("<I", record[pos + blen: pos + blen + 4])[0])
                        pos += 4
                    mtype = "U"
                elif btype in (0x00, 0x01):     # boolean
                    blen = 0
                    data = bool(btype)
                    mtype = "b"
                else:
                    warnings.warn(f"Unknown block type 0x{btype:02X}")
                    blen = 0
                    data = None
                    mtype = " "
            except (IndexError, struct.error) as exc:
                log.debug("Error parsing block at pos %d: %s", pos, exc)
                break

            # Resolve block name
            key_raw = (top_id << 24) + bid_raw
            bid = f"_{mtype}{bid_raw:x}"
            if self.decode:
                if key_raw in self.mapping:
                    bid = self.mapping[key_raw]
                elif bid in self.mapping:
                    bid = self.mapping[bid]

            data = self._parse_value(key_raw, bid, btype, data)
            alldata[bid] = data
            pos += blen

        return alldata

    def map_block_names(self, mapping: Dict) -> None:
        """Register field name mappings (enables human-readable keys)."""
        self.mapping.update(mapping)
        self.decode = True

    def add_parser(self, block_id, function) -> None:
        """Register a custom value parser for a specific block ID."""
        self.parsers[block_id] = function

    def close(self) -> None:
        self._dat.close()
        if self._idx:
            self._idx.close()


# ── User credential decoder ───────────────────────────────────────────────────

class UserDatDecoder:
    """Decode RouterOS user.dat to extract plaintext credentials.

    The password stored in user.dat is XOR-encrypted with:
        key = MD5(username + "283i4jfkai3389") * 16   (256-byte repeating key)

    After CVE-2018-14847 extracts user.dat (and optionally user.idx), this
    class decodes it to retrieve plaintext username/password pairs.

    Args:
        dat_path: Path to user.dat file.
        idx_path: Path to user.idx file (optional, improves parsing reliability).

    References:
        - Password XOR algorithm: Kirils Solovjovs (@KirilsSolovjovs), 2017
          http://hop.02.lv/2Wb
        - https://github.com/0ki/mikrotik-tools/blob/master/decode_user.py
    """

    _MAGIC_SUFFIX = b"283i4jfkai3389"

    _USER_MAPPING = {
        0x0B: "permissions",
        0x1F: "last_login",
        0x1C: "password_set",
        0x01: "username",
        0x11: "password",
        0x02: "group_id",
        0x12: "group_name",
        0x10: "allowed_addresses",
        0x05: "allowed_ip4",
        0x06: "allowed_net4",
    }

    @staticmethod
    def _xor_decrypt(ciphertext: bytes, key: bytes) -> bytes:
        """XOR ciphertext with key (repeating), strip null terminator."""
        result = bytes(a ^ b for a, b in zip(ciphertext, (key * 16)[:len(ciphertext)]))
        # null-terminate
        return result.split(b"\x00")[0]

    @classmethod
    def decode_password(cls, username: str, encrypted_password) -> str:
        """Decrypt a RouterOS password stored in user.dat.

        Args:
            username: Plaintext username (used as key component).
            encrypted_password: Raw bytes or list of ints from user.dat 'password' field.

        Returns:
            Decrypted password string, or empty string on failure.
        """
        if isinstance(encrypted_password, str):
            try:
                encrypted_password = encrypted_password.encode("latin-1")
            except Exception:
                return ""
        if isinstance(encrypted_password, list):
            encrypted_password = bytes(encrypted_password)
        if not encrypted_password:
            return ""

        key = hashlib.md5(username.encode("utf-8") + cls._MAGIC_SUFFIX).digest()
        plaintext = cls._xor_decrypt(encrypted_password, key)
        try:
            return plaintext.decode("utf-8")
        except UnicodeDecodeError:
            return plaintext.decode("latin-1", errors="replace")

    @classmethod
    def from_files(cls, dat_path: str, idx_path: Optional[str] = None) -> List[Dict]:
        """Parse user.dat (and optionally user.idx) and return decoded user records.

        Args:
            dat_path: Path to user.dat
            idx_path: Path to user.idx (optional)

        Returns:
            List of dicts with keys: username, password (plaintext), group_name,
            last_login, allowed_addresses, disabled.
        """
        if not Path(dat_path).exists():
            log.warning("[decoder] user.dat not found at %s", dat_path)
            return []

        decoder = MTDatDecoder(dat_path, idx_path)
        decoder.map_block_names(cls._USER_MAPPING)
        users: List[Dict] = []

        for record in decoder:
            if not record:
                continue
            username = record.get("username", "")
            encrypted_pw = record.get("password", b"")

            if not username:
                continue

            plaintext_pw = cls.decode_password(username, encrypted_pw) if encrypted_pw else ""

            users.append({
                "username":          username,
                "password":          plaintext_pw,
                "group_name":        record.get("group_name", ""),
                "group_id":          record.get("group_id", ""),
                "last_login":        record.get("last_login", ""),
                "allowed_addresses": record.get("allowed_addresses", ""),
                "disabled":          record.get("disabled", False),
                "permissions":       record.get("permissions", ""),
            })

        decoder.close()
        log.info("[decoder] Extracted %d user(s) from %s", len(users), dat_path)
        return users

    @classmethod
    def from_bytes(cls, dat_bytes: bytes, idx_bytes: Optional[bytes] = None) -> List[Dict]:
        """Parse user.dat content provided as raw bytes (e.g., after extraction).

        Args:
            dat_bytes: Raw bytes of user.dat
            idx_bytes: Raw bytes of user.idx (optional)

        Returns:
            List of decoded user dicts.
        """
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".dat", delete=False) as tmp_dat:
            tmp_dat.write(dat_bytes)
            tmp_dat_path = tmp_dat.name

        tmp_idx_path = None
        if idx_bytes:
            with tempfile.NamedTemporaryFile(suffix=".idx", delete=False) as tmp_idx:
                tmp_idx.write(idx_bytes)
                tmp_idx_path = tmp_idx.name

        try:
            return cls.from_files(tmp_dat_path, tmp_idx_path)
        finally:
            os.unlink(tmp_dat_path)
            if tmp_idx_path:
                os.unlink(tmp_idx_path)

    @staticmethod
    def print_table(users: List[Dict]) -> None:
        """Print decoded credentials as a formatted table."""
        if not users:
            print("\n  [decoder] No users found or decryption failed.\n")
            return
        print(f"\n  [decoder] {len(users)} user(s) decoded from user.dat:")
        print(f"  {'Username':20}  {'Password':30}  {'Group':12}  {'Disabled'}")
        print("  " + "-" * 80)
        for u in users:
            pw = u["password"] if u["password"] else "(empty — check if blank default)"
            print(f"  {u['username'][:20]:20}  {pw[:30]:30}  {str(u['group_name'])[:12]:12}  {u['disabled']}")
        print()


# ── Backup file decoder ───────────────────────────────────────────────────────

class BackupDecoder:
    """Decode RouterOS .backup files (unencrypted only).

    RouterOS backup files are archives containing multiple .dat/.idx database
    files. This decoder extracts them to a folder, after which UserDatDecoder
    can decode user.dat to obtain credentials.

    Magic bytes:
        0x88ACA1B1 — standard .backup (unencrypted)
        0xEFA89172 — encrypted .backup (not supported)

    Reference:
        https://github.com/0ki/mikrotik-tools/blob/master/decode_backup.py
    """

    MAGIC_OK      = bytes([0x88, 0xAC, 0xA1, 0xB1])
    MAGIC_ENC     = bytes([0xEF, 0xA8, 0x91, 0x72])

    @classmethod
    def decode(cls, backup_path: str, output_dir: Optional[str] = None) -> List[str]:
        """Extract all .dat/.idx files from a RouterOS .backup.

        Args:
            backup_path: Path to the .backup file.
            output_dir:  Directory to write extracted files. Defaults to
                         ``<backup_path>_contents/``.

        Returns:
            List of extracted file paths.
        """
        real_size = os.path.getsize(backup_path)
        if output_dir is None:
            output_dir = backup_path + "_contents"
        os.makedirs(output_dir, exist_ok=True)

        extracted: List[str] = []

        with open(backup_path, "rb") as f:
            hdr = f.read(4)
            if hdr == cls.MAGIC_ENC:
                raise ValueError("Encrypted RouterOS backup files are not supported. "
                                 "Use /system backup save (without password) to create an unencrypted backup.")
            if real_size < 8 or hdr != cls.MAGIC_OK:
                raise ValueError("Not a valid RouterOS backup file (bad magic bytes).")

            match_size = struct.unpack("<I", f.read(4))[0]
            if match_size != real_size:
                raise ValueError(f"Backup file appears damaged (size mismatch: {match_size} != {real_size})")

            while f.tell() + 4 < match_size:
                name_len = struct.unpack("<I", f.read(4))[0]
                file_name = f.read(name_len).decode("utf-8", errors="replace")
                idx_data  = f.read(struct.unpack("<I", f.read(4))[0])
                dat_data  = f.read(struct.unpack("<I", f.read(4))[0])

                # Sanitize path traversal
                safe_name = re.sub(r"\.{2,}", "_", file_name)
                safe_name = re.sub(r"[/\\]", os.sep, safe_name)

                entry_dir = os.path.join(output_dir, os.path.dirname(safe_name))
                os.makedirs(entry_dir, exist_ok=True)

                for ext, data in ((".idx", idx_data), (".dat", dat_data)):
                    out_path = os.path.join(output_dir, safe_name + ext)
                    with open(out_path, "wb") as out_f:
                        out_f.write(data)
                    extracted.append(out_path)
                    log.info("[backup] Extracted: %s (%d bytes)", out_path, len(data))

        return extracted

    @classmethod
    def extract_credentials(cls, backup_path: str, output_dir: Optional[str] = None) -> List[Dict]:
        """Extract credentials from a .backup file in one step.

        Decodes the backup, locates user.dat/user.idx, then runs UserDatDecoder.

        Args:
            backup_path: Path to the RouterOS .backup file.
            output_dir:  Optional extraction directory.

        Returns:
            List of decoded user credential dicts.
        """
        extracted = cls.decode(backup_path, output_dir)

        # Find user.dat
        dat_files = [p for p in extracted if os.path.basename(p) == "user.dat"]
        idx_files = [p for p in extracted if os.path.basename(p) == "user.idx"]

        if not dat_files:
            log.warning("[backup] No user.dat found in backup — no credentials extracted")
            return []

        idx_path = idx_files[0] if idx_files else None
        return UserDatDecoder.from_files(dat_files[0], idx_path)


# ── Supout.rif section extractor ─────────────────────────────────────────────

class SupoutDecoder:
    """Extract section metadata from a RouterOS supout.rif file.

    The supout.rif diagnostic file is a concatenation of named sections.
    Each section starts with a header containing the section name and its size.
    This decoder lists all sections and can dump specific ones as text.

    Reference:
        https://github.com/0ki/mikrotik-tools/blob/master/decode_supout.py
        https://mikrotik.com/download (Winbox → Diagnostics → Supout.rif)
    """

    @classmethod
    def list_sections(cls, supout_path: str) -> List[Dict]:
        """Return all sections found in the supout.rif file.

        Returns:
            List of dicts with keys: name, offset, size.
        """
        sections = []
        with open(supout_path, "rb") as f:
            data = f.read()

        pos = 0
        while pos < len(data) - 8:
            # Section header: 4-byte magic + name + \x00 + 4-byte size
            if data[pos: pos + 4] != b"\x8b\xbe\xa8\xbc":
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

            sections.append({"name": name, "offset": pos, "size": size})
            pos += size

        log.info("[supout] Found %d section(s) in %s", len(sections), supout_path)
        return sections

    @classmethod
    def dump_section(cls, supout_path: str, section_name: str) -> Optional[str]:
        """Return the text content of a named section.

        Args:
            supout_path:  Path to supout.rif.
            section_name: Section name (e.g. '/system/users', '/ip/address').

        Returns:
            Section content as string, or None if not found.
        """
        with open(supout_path, "rb") as f:
            data = f.read()

        for section in cls.list_sections(supout_path):
            if section["name"] == section_name:
                raw = data[section["offset"]: section["offset"] + section["size"]]
                try:
                    return raw.decode("utf-8")
                except UnicodeDecodeError:
                    return raw.decode("latin-1", errors="replace")

        return None

    @classmethod
    def extract_users_from_supout(cls, supout_path: str) -> List[Dict]:
        """Try to extract user/password data from /system/users section.

        Returns:
            List of dicts {username, password} parsed from text representation.
            Note: passwords in supout are usually blank or hashed — this is
            metadata-only (confirms user existence).
        """
        content = cls.dump_section(supout_path, "/system/users")
        if not content:
            content = cls.dump_section(supout_path, "system/users")
        if not content:
            return []

        users = []
        for line in content.splitlines():
            line = line.strip()
            if not line or line.startswith("#") or line.startswith(";"):
                continue
            # Format: /user add name=admin group=full password=""
            m = re.search(r'name=(\S+)', line)
            if m:
                users.append({
                    "username": m.group(1).strip('"\''),
                    "password": "(from supout — encrypted/blank)",
                })
        return users

