"""
CLI entry point for pip-installed mikrotikapi-bf.

When installed via pip, the `mikrotikapi-bf` and `mikrotik-bf` commands
delegate to the main script, resolving paths relative to the package install.
"""

import os
import sys
from pathlib import Path


def _get_package_root() -> Path:
    """Return the root directory of the installed package."""
    # When installed via pip, this file lives at <site-packages>/mikrotikapi_bf/cli.py
    # The main script is one level up.
    return Path(__file__).parent.parent.resolve()


def nse_path() -> None:
    """Print the path to installed NSE scripts (for use with nmap --script)."""
    nse_dir = _get_package_root() / "nse"
    if nse_dir.exists():
        print(str(nse_dir))
    else:
        print("NSE scripts not found. Reinstall with: pip install --force-reinstall mikrotikapi-bf",
              file=sys.stderr)
        sys.exit(1)


def main() -> None:
    """Main entry point — delegates to mikrotikapi-bf.py."""
    root = _get_package_root()
    main_script = root / "mikrotikapi-bf.py"

    if not main_script.exists():
        print(f"[ERROR] Main script not found at {main_script}", file=sys.stderr)
        sys.exit(1)

    # Add package root to sys.path so relative imports (core/, modules/, xpl/) work
    if str(root) not in sys.path:
        sys.path.insert(0, str(root))

    # Handle --nse-path flag before passing to main script
    if "--nse-path" in sys.argv:
        nse_path()
        return

    # Load .env if present (python-dotenv)
    try:
        from dotenv import load_dotenv
        env_file = root / ".env"
        if env_file.exists():
            load_dotenv(env_file, override=False)
    except ImportError:
        pass

    # Execute the main script in its own namespace
    import runpy
    sys.argv[0] = str(main_script)
    runpy.run_path(str(main_script), run_name="__main__")
