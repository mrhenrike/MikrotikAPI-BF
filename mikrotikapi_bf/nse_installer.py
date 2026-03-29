"""
NSE Auto-Installer — MikrotikAPI-BF
=====================================
Detects Nmap installation on Windows, Linux, and macOS and copies
the bundled NSE scripts to the Nmap scripts directory automatically.

Called:
    - During `pip install mikrotikapi-bf` (via setup.py post_install hook)
    - During `pip install --upgrade mikrotikapi-bf` (same hook)
    - Manually via: `mikrotikapi-install-nse`
    - Via CLI flag: `mikrotikapi-bf --install-nse`
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path
from typing import List, Optional


# ── Nmap script directory detection ──────────────────────────────────────────

def _find_nmap_scripts_dir() -> Optional[Path]:
    """Locate the Nmap scripts directory on the current OS.

    Detection order:
      1. ``nmap --version`` binary in PATH → resolve sibling scripts/
      2. Well-known default paths per OS
      3. NMAP_DIR environment variable override

    Returns:
        Path to the Nmap scripts directory, or None if not found.
    """
    # 0. Environment override
    if env_dir := os.getenv("NMAP_SCRIPTS_DIR"):
        p = Path(env_dir)
        if p.is_dir():
            return p

    # 1. nmap binary in PATH → scripts/ sibling
    nmap_bin = shutil.which("nmap")
    if nmap_bin:
        nmap_path = Path(nmap_bin).resolve()
        # On Linux/macOS: /usr/bin/nmap  → /usr/share/nmap/scripts/
        # On Windows:     C:\...\Nmap\nmap.exe → C:\...\Nmap\scripts\
        candidates = [
            nmap_path.parent / "scripts",                        # Windows
            nmap_path.parent.parent / "share" / "nmap" / "scripts",  # Linux/macOS
            nmap_path.parent.parent / "lib" / "nmap" / "scripts",    # Homebrew alt
        ]
        for c in candidates:
            if c.is_dir():
                return c

    # 2. Well-known paths per OS
    system = platform.system()
    if system == "Windows":
        candidates = [
            Path(r"C:\Program Files (x86)\Nmap\scripts"),
            Path(r"C:\Program Files\Nmap\scripts"),
            Path(os.environ.get("PROGRAMFILES", "") + r"\Nmap\scripts"),
        ]
    elif system == "Darwin":  # macOS
        candidates = [
            Path("/usr/local/share/nmap/scripts"),          # Intel Homebrew
            Path("/opt/homebrew/share/nmap/scripts"),        # ARM Homebrew
            Path("/opt/local/share/nmap/scripts"),           # MacPorts
            Path("/usr/share/nmap/scripts"),
        ]
    else:  # Linux and other Unix
        candidates = [
            Path("/usr/share/nmap/scripts"),
            Path("/usr/local/share/nmap/scripts"),
            Path("/opt/nmap/share/nmap/scripts"),
            Path("/snap/nmap/current/usr/share/nmap/scripts"),
        ]

    for c in candidates:
        if c.is_dir():
            return c

    return None


def _get_bundled_nse_dir() -> Optional[Path]:
    """Return the path to the bundled nse/ directory inside the installed package."""
    # When installed via pip, this file is at:
    # <site-packages>/mikrotikapi_bf/nse_installer.py
    # The NSE scripts are at:
    # <site-packages>/nse/*.nse  (package root)
    pkg_root = Path(__file__).parent.parent.resolve()
    nse_dir = pkg_root / "nse"
    if nse_dir.is_dir():
        return nse_dir
    # Fallback: dev/source checkout
    fallback = Path(__file__).parent.parent / "nse"
    return fallback if fallback.is_dir() else None


def _update_script_db(nmap_bin: Optional[str]) -> None:
    """Run `nmap --script-updatedb` to register newly copied scripts."""
    if nmap_bin:
        try:
            subprocess.run([nmap_bin, "--script-updatedb"],
                           capture_output=True, timeout=30)
        except Exception:
            pass


# ── Main install function ─────────────────────────────────────────────────────

def install_nse(verbose: bool = True) -> bool:
    """Copy bundled NSE scripts to the Nmap scripts directory.

    Args:
        verbose: Print progress messages.

    Returns:
        True if at least one script was copied, False otherwise.
    """
    def _log(msg: str) -> None:
        if verbose:
            print(msg)

    nmap_dir = _find_nmap_scripts_dir()
    if not nmap_dir:
        _log(
            "  [nse-install] Nmap scripts directory not found.\n"
            "  Install Nmap from https://nmap.org/download.html and re-run:\n"
            "    mikrotikapi-install-nse\n"
            "  Or set NMAP_SCRIPTS_DIR=/path/to/nmap/scripts and re-run."
        )
        return False

    nse_src = _get_bundled_nse_dir()
    if not nse_src or not nse_src.is_dir():
        _log("  [nse-install] Bundled NSE directory not found. Reinstall the package.")
        return False

    scripts = list(nse_src.glob("*.nse"))
    if not scripts:
        _log("  [nse-install] No .nse files found in package.")
        return False

    copied: List[str] = []
    skipped: List[str] = []
    errors: List[str] = []

    for src in scripts:
        dst = nmap_dir / src.name
        try:
            shutil.copy2(src, dst)
            copied.append(src.name)
        except PermissionError:
            errors.append(f"{src.name} (permission denied — try sudo / admin)")
        except Exception as exc:
            errors.append(f"{src.name} ({exc})")

    if copied:
        _log(f"  [nse-install] Copied {len(copied)} NSE script(s) to {nmap_dir}:")
        for s in copied:
            _log(f"    ✓ {s}")
        # Update Nmap script database
        nmap_bin = shutil.which("nmap")
        _update_script_db(nmap_bin)
        _log("  [nse-install] Script database updated. Run: nmap --script-updatedb")

    if errors:
        _log(f"  [nse-install] {len(errors)} error(s):")
        for e in errors:
            _log(f"    ✗ {e}")
        if platform.system() != "Windows":
            _log("  Tip: run with sudo: sudo mikrotikapi-install-nse")

    return bool(copied)


# ── CLI entry point ───────────────────────────────────────────────────────────

def install_nse_cli() -> None:
    """Console script entry point: `mikrotikapi-install-nse`."""
    import argparse
    parser = argparse.ArgumentParser(
        prog="mikrotikapi-install-nse",
        description="Copy MikrotikAPI-BF NSE scripts to the Nmap scripts directory.",
    )
    parser.add_argument(
        "--nmap-scripts-dir", metavar="DIR",
        help="Override auto-detected Nmap scripts directory.",
    )
    parser.add_argument("--quiet", action="store_true", help="Suppress output.")
    args = parser.parse_args()

    if args.nmap_scripts_dir:
        os.environ["NMAP_SCRIPTS_DIR"] = args.nmap_scripts_dir

    ok = install_nse(verbose=not args.quiet)
    sys.exit(0 if ok else 1)
