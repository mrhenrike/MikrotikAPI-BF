#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Author: André Henrique (LinkedIn/X: @mrhenrike)

"""
Canonical version source — MikrotikAPI-BF
==========================================
Single source of truth for the project version.
All modules, scripts, and build tools import from here.

Usage
-----
    from version import __version__               # "3.5.1"
    from version import VERSION                   # (3, 5, 1)
    from version import MAJOR, MINOR, PATCH       # 3, 5, 1

Versioning scheme: MAJOR.MINOR.PATCH
    MAJOR — breaking API or architecture change
    MINOR — new feature (backward compatible)
    PATCH — bug fix, hotfix, doc-only update
"""

# ── Canonical version tuple ───────────────────────────────────────────────────
VERSION: tuple = (3, 5, 2)

MAJOR: int = VERSION[0]
MINOR: int = VERSION[1]
PATCH: int = VERSION[2]

# ── String representations ────────────────────────────────────────────────────
__version__: str = ".".join(str(x) for x in VERSION)

# Alias used throughout the codebase
_VERSION: str = __version__


def version_tuple() -> tuple:
    """Return the version as a (major, minor, patch) tuple."""
    return VERSION


def version_string() -> str:
    """Return the version as a 'major.minor.patch' string."""
    return __version__


def version_info() -> str:
    """Return a human-readable version line for banners and --version output."""
    return f"MikrotikAPI-BF v{__version__}"


if __name__ == "__main__":
    print(__version__)

