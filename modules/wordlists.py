#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Smart Wordlist Manager — MikrotikAPI-BF
=========================================
Intelligent wordlist management for Mikrotik RouterOS pentesting.
Combines built-in defaults, file-based wordlists, and target-aware combinations.
"""

import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple


class SmartWordlistManager:
    """
    Manage and generate credential wordlists for Mikrotik targets.

    Args:
        wordlists_dir: Directory to look for external wordlist files.
    """

    # Built-in Mikrotik-specific defaults
    _DEFAULT_USERS: List[str] = [
        "admin", "mikrotik", "routeros", "user", "manager",
        "support", "guest", "operator", "tech", "root",
        "administrator", "info", "adm",
    ]

    _DEFAULT_PASSWORDS: List[str] = [
        "", "admin", "password", "mikrotik", "routeros",
        "123456", "password123", "admin123", "mikrotik123",
        "routeros123", "12345678", "qwerty", "abc123",
        "1234567890", "111111", "1q2w3e4r", "letmein",
        "welcome", "monkey", "dragon", "master",
    ]

    def __init__(self, wordlists_dir: str = "wordlists") -> None:
        self.wordlists_dir = Path(wordlists_dir)
        # Known external file names (if placed in wordlists_dir)
        self._external_files: Dict[str, str] = {
            "usernames": "username_br.lst",
            "passwords": "labs_passwords.lst",
            "users": "labs_users.lst",
            "mikrotik_pass": "labs_mikrotik_pass.lst",
        }

    # ------------------------------------------------------------------
    # Loading
    # ------------------------------------------------------------------

    def load_file(self, path: Path) -> List[str]:
        """Load a wordlist file, one entry per line."""
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                return [ln.strip() for ln in fh if ln.strip()]
        except Exception:
            return []

    def load_external(self, key: str) -> List[str]:
        """Load one of the known external wordlist files if present."""
        filename = self._external_files.get(key)
        if not filename:
            return []
        return self.load_file(self.wordlists_dir / filename)

    # ------------------------------------------------------------------
    # Wordlist retrieval
    # ------------------------------------------------------------------

    def get_usernames(self, include_external: bool = True) -> List[str]:
        """Return the merged username list."""
        users = list(self._DEFAULT_USERS)
        if include_external:
            for key in ("usernames", "users"):
                users.extend(self.load_external(key))
        return self._dedup(users)

    def get_passwords(self, include_external: bool = True) -> List[str]:
        """Return the merged password list."""
        pwds = list(self._DEFAULT_PASSWORDS)
        if include_external:
            for key in ("passwords", "mikrotik_pass"):
                pwds.extend(self.load_external(key))
        return self._dedup(pwds)

    def get_combinations(
        self,
        users: Optional[List[str]] = None,
        passwords: Optional[List[str]] = None,
    ) -> List[Tuple[str, str]]:
        """Return all (user, password) pairs."""
        u = users or self.get_usernames()
        p = passwords or self.get_passwords()
        return [(usr, pwd) for usr in u for pwd in p]

    # ------------------------------------------------------------------
    # Target-aware generation
    # ------------------------------------------------------------------

    def generate_smart_combinations(self, target_info: Dict) -> List[Tuple[str, str]]:
        """
        Generate a prioritised wordlist based on target fingerprint data.

        Args:
            target_info: Dict as returned by MikrotikFingerprinter.

        Returns:
            Deduplicated list of (username, password) tuples, with
            target-specific guesses placed first.
        """
        specific = self._target_specific(target_info)
        generic = self.get_combinations()
        seen = set(specific)
        for combo in generic:
            if combo not in seen:
                seen.add(combo)
                specific.append(combo)
        return specific

    def _target_specific(self, info: Dict) -> List[Tuple[str, str]]:
        combos: List[Tuple[str, str]] = []
        ip = info.get("target", "")
        hostname = info.get("hostname", "")
        version = info.get("routeros_version", "")
        model = info.get("model", "")

        if ip:
            parts = ip.split(".")
            if len(parts) == 4:
                combos += [("admin", parts[-1]), ("admin", ip)]

        if hostname:
            hn = hostname.lower()
            combos += [("admin", hn)]
            if "." in hostname:
                company = hostname.split(".")[0].lower()
                combos += [("admin", company)]

        if version:
            ver_clean = re.sub(r"[^\d.]", "", version)
            combos += [("admin", ver_clean)]

        if model:
            combos += [("admin", model.lower())]

        return combos

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def get_wordlist_stats(self) -> Dict:
        """Return statistics about available wordlists."""
        ext: Dict[str, int] = {}
        for key in self._external_files:
            words = self.load_external(key)
            if words:
                ext[key] = len(words)
        return {
            "mikrotik_defaults": len(self._DEFAULT_USERS),
            "mikrotik_passwords": len(self._DEFAULT_PASSWORDS),
            "total_combinations": len(self._DEFAULT_USERS) * len(self._DEFAULT_PASSWORDS),
            "external_wordlists": ext,
        }

    @staticmethod
    def _dedup(lst: List[str]) -> List[str]:
        seen: set = set()
        out: List[str] = []
        for item in lst:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out

    # ------------------------------------------------------------------
    # RouterOS pattern generator (native, no WFH dependency)
    # ------------------------------------------------------------------

    def generate_routeros_patterns(self, count: int = 0) -> List[str]:
        """Generate RouterOS-specific password candidates natively.

        Applies pattern rules derived from real RouterOS credential surveys:
            - Date/serial combinations (YYYY, YYYYMM, DDMMYYYY)
            - Model number variants (e.g. ccr1009, rb750, hex)
            - Admin pattern expansions (admin@hostname, admin+year)
            - ISP defaults (common Brazilian/LATAM carrier patterns)
            - Numeric PIN patterns (4-8 digits, common sequences)
            - Keyboard walk patterns (QWERTY rows, shifted)
            - Corporate portal defaults (company+year, company+year2)

        No external file or subprocess required - all logic is native.

        Args:
            count: Maximum number of candidates to return (0 = all).

        Returns:
            Deduplicated list of password candidates, most probable first.
        """
        from datetime import datetime as _dt

        candidates: List[str] = []
        year = _dt.now().year

        # --- Priority 1: RouterOS factory defaults ---
        candidates += [
            "", "admin", "mikrotik", "routeros",
        ]

        # --- Priority 2: Common RouterOS model names ---
        _models = [
            "ccr1009", "ccr1016", "ccr1036", "ccr1072",
            "ccr2004", "ccr2116", "ccr2216",
            "rb750", "rb750r2", "rb750gr3", "rb760igs",
            "rb951", "rb951ui", "rb951g",
            "rb450", "rb450gx4", "rb433", "rb493g",
            "crs305", "crs309", "crs317", "crs326", "crs354",
            "hex", "hexs", "hap", "haplite", "hapm", "hapmini",
            "wap", "wapr", "wap60gx3", "lhg", "lhgxlhp",
            "ltap", "ltapmin", "sxt", "sxtlite",
            "cap", "capl", "capxl",
        ]
        for m in _models:
            candidates += [m, m.upper(), m.capitalize()]

        # --- Priority 3: Year/date patterns ---
        for y in range(year - 5, year + 2):
            ys = str(y)
            candidates += [
                ys, f"admin{ys}", f"mikrotik{ys}", f"Mikrotik{ys}",
                f"router{ys}", f"{ys}admin", f"pass{ys}",
                ys[-2:],  # 2-digit year
                f"mikrotik{ys[-2:]}",
                f"admin@{ys}",
            ]
            for m in range(1, 13):
                candidates.append(f"{ys}{m:02d}")
                candidates.append(f"{m:02d}{ys}")

        # --- Priority 4: ISP/carrier defaults (Brazilian/LATAM) ---
        _isp_bases = [
            "vivo", "claro", "oi", "tim", "nextel", "net",
            "intelig", "algar", "brisanet", "sky", "sercomtel",
            "telebras", "embratel", "ctbc",
            "telecom", "telelink", "multiplay", "unicom",
            "ispnet", "netlink", "net123",
        ]
        for base in _isp_bases:
            candidates += [
                base, f"{base}123", f"{base}1234",
                f"{base}@123", base.capitalize(),
                f"{base.capitalize()}123",
                f"{base}{year % 100:02d}",
                f"{base}{year}",
            ]

        # --- Priority 5: PIN patterns ---
        # Common short PINs
        _common_4digit = [
            "0000", "1111", "2222", "3333", "4444", "5555",
            "6666", "7777", "8888", "9999", "1234", "4321",
            "1122", "2211", "1212", "2121", "0001", "1000",
            "1001", "1357", "2468",
        ]
        # Extend to 6, 8 digits
        candidates += _common_4digit
        candidates += [p + p for p in _common_4digit]  # 8-digit repeat
        candidates += [p + "00" for p in _common_4digit]  # 6-digit

        # --- Priority 6: Keyboard walk patterns ---
        _keyboard_walks = [
            "qwerty", "qwerty123", "qwertyuiop",
            "asdfgh", "asdfghjkl", "zxcvbn", "zxcvbnm",
            "1qaz2wsx", "1q2w3e4r", "1q2w3e",
            "qazwsx", "wsxedc", "1234qwer",
            "q1w2e3r4", "abcd1234",
        ]
        candidates += _keyboard_walks

        # --- Priority 7: Corporate portal defaults ---
        _corp_patterns = [
            "123456", "password", "password1", "Password1",
            "admin123", "Admin123", "ADMIN123",
            "senha123", "Senha123", "senha@123",
            "mudar@123", "mudar123", "Mudar123",
            "trocar123", "alterar123",
            "Welcome1", "welcome1", "Welcome123",
            "changeme", "changeme1", "ChangeMe1",
            "admin@2024", f"admin@{year}",
            "router123", "Router123",
            "netadmin", "netadmin1",
        ]
        candidates += _corp_patterns

        # --- Priority 8: Mixed variants of top passwords ---
        _top_bases = ["admin", "mikrotik", "router", "senha", "pass"]
        _suffixes = ["1", "12", "123", "1234", "!", "@", "#", "01", "02"]
        for base in _top_bases:
            for suf in _suffixes:
                candidates += [
                    f"{base}{suf}",
                    f"{base.capitalize()}{suf}",
                    f"{base.upper()}{suf}",
                ]

        # Deduplicate preserving order
        result = self._dedup(candidates)

        if count > 0:
            return result[:count]
        return result
