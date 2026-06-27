#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""Resolve WFH lab wordlists from sibling WordListsForHacking/labs submodule."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Tuple

_LABS_FILES = {
    "users": "labs_users.lst",
    "passwords": "labs_passwords.lst",
    "mikrotik_pass": "labs_mikrotik_pass.lst",
}


def _repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def wfh_labs_dir() -> Path:
    """Directory containing labs_users.lst, labs_passwords.lst, etc."""
    override = os.environ.get("WFH_LABS_DIR", "").strip()
    if override:
        return Path(override).expanduser().resolve()
    sibling = _repo_root().parent / "WordListsForHacking" / "labs"
    if sibling.is_dir():
        return sibling
    return _repo_root() / "wordlists" / "labs"


def lab_wordlist(name: str) -> Path:
    """Return path to a named lab wordlist; raises FileNotFoundError if missing."""
    if name not in _LABS_FILES:
        raise KeyError(f"Unknown lab wordlist: {name!r} (choose: {', '.join(_LABS_FILES)})")
    path = wfh_labs_dir() / _LABS_FILES[name]
    if not path.is_file():
        raise FileNotFoundError(
            f"Lab wordlist not found: {path}\n"
            "Clone WordListsForHacking alongside MikrotikAPI-BF or set WFH_LABS_DIR."
        )
    return path


def default_lab_credentials() -> Tuple[str, str]:
    """
    Default WFH lab user + password lists (full pool: labs_users + labs_passwords).

    Override via MIKROTIK_BF_USERLIST / MIKROTIK_BF_PASSLIST.
    Use MIKROTIK_BF_PASSLIST=.../labs_mikrotik_pass.lst for RouterOS-only subset.
    """
    userlist = os.environ.get("MIKROTIK_BF_USERLIST", "").strip()
    passlist = os.environ.get("MIKROTIK_BF_PASSLIST", "").strip()
    if userlist and passlist:
        return userlist, passlist
    return str(lab_wordlist("users")), str(lab_wordlist("passwords"))


def default_lab_credentials_mikrotik() -> Tuple[str, str]:
    """Subset: labs_users.lst + labs_mikrotik_pass.lst."""
    return str(lab_wordlist("users")), str(lab_wordlist("mikrotik_pass"))
