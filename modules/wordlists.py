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
