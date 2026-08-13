"""Basic package import smoke tests for MikrotikAPI-BF."""

from __future__ import annotations

import importlib
import re
from pathlib import Path


def test_import_mikrotikapi_bf() -> None:
    """Package must import cleanly for CI and local installs."""
    module = importlib.import_module("mikrotikapi_bf")
    assert module is not None


def test_version_matches_canonical_source() -> None:
    """Exposed package version must match version.py and use X.Y.Z."""
    module = importlib.import_module("mikrotikapi_bf")
    version = getattr(module, "__version__", None)
    assert isinstance(version, str)
    assert re.fullmatch(r"\d+\.\d+\.\d+", version), version

    root = Path(__file__).resolve().parents[1]
    version_py = (root / "version.py").read_text(encoding="utf-8")
    match = re.search(r"VERSION:\s*tuple\s*=\s*\((\d+),\s*(\d+),\s*(\d+)\)", version_py)
    assert match is not None, "canonical VERSION tuple not found in version.py"
    expected = ".".join(match.groups())
    assert version == expected